#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import os
import re
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Iterable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urljoin, urlsplit
from urllib.request import Request, urlopen


URL_PATTERN = re.compile(
    r"^(?P<root>.*/upload)/(?P<ym>\d{6})/(?P<day>\d{2})/"
    r"(?P<digits>\d{18})(?P<ext>\.[A-Za-z0-9]+)$"
)
ARTICLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")

DATE_DIGITS = 8
HOUR_DIGITS = 2
MINUTE_DIGITS = 2
SECOND_DIGITS = 2
FRACTION_DIGITS = 4
TIMESTAMP_DIGITS = DATE_DIGITS + HOUR_DIGITS + MINUTE_DIGITS + SECOND_DIGITS + FRACTION_DIGITS
MAX_HOUR = 23
MAX_MINUTE = 59
MAX_SECOND = 59
MAX_FRACTION = 10**FRACTION_DIGITS - 1
# 分钟最多进位次数；0 表示只检测当前分钟剩余候选。
DEFAULT_MINUTE_INCREMENT_COUNT = 1
# 单个 URL 的临时错误重试次数。
REQUEST_RETRIES = 3
# 重试退避基准秒数；第 n 次重试前等待 retry_backoff * n。
RETRY_BACKOFF_SECONDS = 0.5
DEFAULT_BATCH_TABLE = r"/www/60.csv"
DEFAULT_BATCH_OUTPUT_DIR = r"/www/probe_json"
COMPLETED_MARK = "已完成"


@dataclass(frozen=True)
class SeedInfo:
    scheme: str
    netloc: str
    root: str
    dir_ym: str
    dir_day: str
    ext: str
    date_hour_prefix: str
    minute: int
    second: int
    fraction: int


@dataclass(frozen=True)
class Hit:
    url: str
    status: int
    content_type: str
    content_length: Optional[int]
    file_name: str
    date_hour_prefix: str
    minute: int
    second: int
    fraction: int
    checked_at: str


@dataclass(frozen=True)
class RetryFailure:
    url: str
    status: Optional[int]
    error: str
    minute: int
    second: int
    fraction: int
    retry_count: int
    request_count: int
    checked_at: str


@dataclass(frozen=True)
class DetectionResult:
    hit: Optional[Hit]
    retry_failure: Optional[RetryFailure]


@dataclass(frozen=True)
class ProbeSummary:
    checked: int
    total: int
    found: int
    retry_failed: int
    elapsed_seconds: float
    interrupted: bool

    def message(self) -> str:
        label = "中断" if self.interrupted else "完成"
        return (
            f"[{label}] checked={self.checked}/{self.total}, found={self.found}, "
            f"retry_failed={self.retry_failed}, elapsed={self.elapsed_seconds:.2f}s"
        )


@dataclass(frozen=True)
class BatchItem:
    row_number: int
    article_url: str
    image_url: str
    article_id: str


@dataclass(frozen=True)
class BatchReadResult:
    items: list[BatchItem]
    skipped_completed: int
    data_rows: int


class SafePrinter:
    def __init__(self) -> None:
        self._lock = Lock()

    def line(self, text: str) -> None:
        with self._lock:
            print(text, flush=True)


def parse_seed_url(seed_url: str) -> SeedInfo:
    parsed = urlsplit(seed_url.strip())
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("URL 必须包含协议和域名，例如 http://example.com/upload/...")

    match = URL_PATTERN.match(parsed.path)
    if not match:
        raise ValueError(
            "无法识别 URL 格式，期望格式："
            "/upload/YYYYMM/DD/18位数字.ext"
        )

    digits = match.group("digits")
    dir_ym = match.group("ym")
    dir_day = match.group("day")
    date_part = digits[:DATE_DIGITS]
    hour = int(digits[DATE_DIGITS : DATE_DIGITS + HOUR_DIGITS])
    minute_start = DATE_DIGITS + HOUR_DIGITS
    second_start = minute_start + MINUTE_DIGITS
    fraction_start = second_start + SECOND_DIGITS
    minute = int(digits[minute_start:second_start])
    second = int(digits[second_start:fraction_start])
    fraction = int(digits[fraction_start:TIMESTAMP_DIGITS])

    if dir_ym != date_part[:6] or dir_day != date_part[6:8]:
        raise ValueError("目录日期与文件名时间不一致，停止枚举以避免生成错误路径")
    if hour > MAX_HOUR:
        raise ValueError("文件名小时必须在 00-23 范围内")
    if minute > MAX_MINUTE:
        raise ValueError("文件名分钟必须在 00-59 范围内")
    if second > MAX_SECOND:
        raise ValueError("文件名秒必须在 00-59 范围内")

    return SeedInfo(
        scheme=parsed.scheme,
        netloc=parsed.netloc,
        root=match.group("root"),
        dir_ym=dir_ym,
        dir_day=dir_day,
        ext=match.group("ext"),
        date_hour_prefix=digits[: DATE_DIGITS + HOUR_DIGITS],
        minute=minute,
        second=second,
        fraction=fraction,
    )


def build_url(seed: SeedInfo, minute: int, second: int, fraction: int) -> str:
    file_name = (
        f"{seed.date_hour_prefix}"
        f"{minute:02d}{second:02d}{fraction:0{FRACTION_DIGITS}d}"
        f"{seed.ext}"
    )
    return (
        f"{seed.scheme}://{seed.netloc}"
        f"{seed.root}/{seed.dir_ym}/{seed.dir_day}/{file_name}"
    )


def iter_candidates(
        seed: SeedInfo,
        minute_increment_count: int,
        include_seed: bool = True,
) -> Iterable[tuple[str, int, int, int]]:
    max_minute = min(MAX_MINUTE, seed.minute + minute_increment_count)
    for minute in range(seed.minute, max_minute + 1):
        start_second = seed.second if minute == seed.minute else 0
        for second in range(start_second, MAX_SECOND + 1):
            if minute == seed.minute and second == seed.second:
                start_fraction = seed.fraction if include_seed else seed.fraction + 1
            else:
                start_fraction = 0

            if start_fraction > MAX_FRACTION:
                continue

            for fraction in range(start_fraction, MAX_FRACTION + 1):
                yield (
                    build_url(seed, minute, second, fraction),
                    minute,
                    second,
                    fraction,
                )


def count_candidates(seed: SeedInfo, minute_increment_count: int) -> int:
    max_minute = min(MAX_MINUTE, seed.minute + minute_increment_count)
    current_minute_total = (
            (MAX_SECOND - seed.second) * (MAX_FRACTION + 1)
            + (MAX_FRACTION - seed.fraction + 1)
    )
    extra_minute_count = max_minute - seed.minute
    full_minute_total = (MAX_SECOND + 1) * (MAX_FRACTION + 1)
    return current_minute_total + extra_minute_count * full_minute_total


def request_status(
        url: str,
        timeout: float,
        user_agent: str,
        method: str,
) -> tuple[Optional[int], dict[str, str], Optional[str]]:
    headers = {"User-Agent": user_agent}
    if method == "GET":
        headers["Range"] = "bytes=0-0"

    request = Request(url, headers=headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), None
    except HTTPError as exc:
        return exc.code, dict(exc.headers.items()), None
    except (URLError, TimeoutError, OSError) as exc:
        return None, {}, str(exc)


def detect_url(
        url: str,
        minute: int,
        second: int,
        fraction: int,
        args: argparse.Namespace,
        printer: SafePrinter,
) -> DetectionResult:
    if args.delay > 0:
        time.sleep(args.delay)

    attempt = 0
    while True:
        status, headers, error = request_status(
            url=url,
            timeout=args.timeout,
            user_agent=args.user_agent,
            method=args.method,
        )

        if args.method == "HEAD" and status in {403, 405, 501} and args.fallback_get:
            status, headers, error = request_status(
                url=url,
                timeout=args.timeout,
                user_agent=args.user_agent,
                method="GET",
            )

        if not should_retry(status, error, attempt, args.retries):
            break

        attempt += 1
        reason = error if error else f"HTTP {status}"
        printer.line(f"[RETRY {attempt}/{args.retries}] {url} -> {reason}")
        if args.retry_backoff > 0:
            time.sleep(args.retry_backoff * attempt)

    if status == 200:
        file_name = url.rsplit("/", 1)[-1]
        hit = Hit(
            url=url,
            status=200,
            content_type=headers.get("Content-Type", ""),
            content_length=parse_content_length(headers.get("Content-Length")),
            file_name=file_name,
            date_hour_prefix=file_name[: DATE_DIGITS + HOUR_DIGITS],
            minute=minute,
            second=second,
            fraction=fraction,
            checked_at=datetime.now(timezone.utc).isoformat(),
        )
        printer.line(f"[200] {url}")
        return DetectionResult(hit=hit, retry_failure=None)

    retry_failure = None
    if is_retryable_failure(status, error):
        retry_failure = RetryFailure(
            url=url,
            status=status,
            error=error or f"HTTP {status}",
            minute=minute,
            second=second,
            fraction=fraction,
            retry_count=attempt,
            request_count=attempt + 1,
            checked_at=datetime.now(timezone.utc).isoformat(),
        )

    if error:
        printer.line(f"[ERR] {url} -> {error}")
    elif not (args.quiet_404 and status == 404):
        printer.line(f"[{status}] {url}")

    return DetectionResult(hit=None, retry_failure=retry_failure)


def should_retry(
        status: Optional[int],
        error: Optional[str],
        attempt: int,
        retries: int,
) -> bool:
    if attempt >= retries:
        return False
    return is_retryable_failure(status, error)


def is_retryable_failure(status: Optional[int], error: Optional[str]) -> bool:
    if error:
        return True
    return status in {408, 429, 500, 502, 503, 504}


def parse_content_length(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def dump_hits(
        output_path: str,
        hits: list[Hit],
        summary: Optional[ProbeSummary] = None,
        article_url: Optional[str] = None,
        seed_url: Optional[str] = None,
) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    tmp_path = f"{output_path}.tmp"
    payload = {
        "summary": summary.message() if summary else "",
        "summary_data": asdict(summary) if summary else None,
        "article_url": article_url or "",
        "seed_url": seed_url or "",
        "results": [asdict(item) for item in hits],
    }
    with open(tmp_path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, ensure_ascii=False)
        file.write("\n")
    os.replace(tmp_path, output_path)


def dump_retry_failures(output_path: str, failures: list[RetryFailure]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    tmp_path = f"{output_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as file:
        json.dump([asdict(item) for item in failures], file, indent=2, ensure_ascii=False)
        file.write("\n")
    os.replace(tmp_path, output_path)


def load_retry_failures(output_path: str) -> list[RetryFailure]:
    if not os.path.exists(output_path):
        return []
    with open(output_path, "r", encoding="utf-8") as file:
        data = json.load(file)
    return [RetryFailure(**item) for item in data]


def default_retry_output_path(output_path: str) -> str:
    base, ext = os.path.splitext(output_path)
    return f"{base}_retry_failed_tmp{ext or '.json'}"


def store_detection_result(
        result: DetectionResult,
        hits: list[Hit],
        retry_failures: list[RetryFailure],
        output_path: str,
        retry_output_path: str,
) -> None:
    if result.hit:
        hits.append(result.hit)
        dump_hits(output_path, hits)
        return

    if result.retry_failure:
        retry_failures.append(result.retry_failure)
        dump_retry_failures(retry_output_path, retry_failures)


def run_final_retries(
        failures: list[RetryFailure],
        args: argparse.Namespace,
        printer: SafePrinter,
        hits: list[Hit],
        output_path: str,
        retry_output_path: str,
) -> list[RetryFailure]:
    if not failures:
        return []

    printer.line(f"[最终重试] 待重试数量: {len(failures)}")
    final_failures: list[RetryFailure] = []
    checked = 0
    found_before = len(hits)

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        failure_iter = iter(failures)
        pending = set()
        exhausted = False
        max_pending = args.workers * 4

        while pending or not exhausted:
            while not exhausted and len(pending) < max_pending:
                try:
                    failure = next(failure_iter)
                except StopIteration:
                    exhausted = True
                    break

                pending.add(
                    executor.submit(
                        detect_url,
                        failure.url,
                        failure.minute,
                        failure.second,
                        failure.fraction,
                        args,
                        printer,
                    )
                )

            if not pending:
                break

            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                checked += 1
                try:
                    result = future.result()
                except Exception as exc:
                    printer.line(f"[ERR] final retry worker failed -> {exc}")
                    continue

                if result.hit:
                    hits.append(result.hit)
                    dump_hits(output_path, hits)

                if result.retry_failure:
                    final_failures.append(result.retry_failure)
                    dump_retry_failures(retry_output_path, final_failures)

                if checked % 100 == 0:
                    printer.line(
                        f"[最终重试进度] checked={checked}/{len(failures)}, "
                        f"recovered={len(hits) - found_before}, "
                        f"still_failed={len(final_failures)}"
                    )

    dump_hits(output_path, hits)
    dump_retry_failures(retry_output_path, final_failures)
    printer.line(
        f"[最终重试完成] checked={checked}/{len(failures)}, "
        f"recovered={len(hits) - found_before}, still_failed={len(final_failures)}"
    )
    return final_failures


def extract_article_id(article_url: str) -> str:
    parsed = urlsplit(article_url.strip())
    for key, value in parse_qsl(parsed.query):
        if key.lower() == "id" and value.strip():
            article_id = value.strip()
            break
    else:
        raise ValueError(f"文章 URL 缺少 id 参数：{article_url}")

    if not ARTICLE_ID_PATTERN.match(article_id):
        raise ValueError(f"文章 id 包含不适合作为文件名的字符：{article_id}")
    return article_id


def find_column_index(headers: list[str], candidates: tuple[str, ...]) -> Optional[int]:
    normalized = [header.strip().lower() for header in headers]
    for candidate in candidates:
        name = candidate.lower()
        if name in normalized:
            return normalized.index(name)
    return None


def row_is_completed(row: list[str]) -> bool:
    return any(COMPLETED_MARK in cell.strip() for cell in row)


def read_csv_rows(table_path: str) -> list[list[str]]:
    last_error: Optional[UnicodeDecodeError] = None
    for encoding in ("utf-8-sig", "gb18030"):
        try:
            with open(table_path, "r", encoding=encoding, newline="") as file:
                return [row for row in csv.reader(file)]
        except UnicodeDecodeError as exc:
            last_error = exc

    raise last_error or UnicodeDecodeError("utf-8", b"", 0, 1, "无法读取 CSV")


def write_csv_rows(table_path: str, rows: list[list[str]]) -> None:
    tmp_path = f"{table_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8-sig", newline="") as file:
        writer = csv.writer(file)
        writer.writerows(rows)
    os.replace(tmp_path, table_path)


def mark_batch_row_completed(table_path: str, row_number: int) -> None:
    rows = read_csv_rows(table_path)
    row_index = row_number - 1
    if row_index < 0 or row_index >= len(rows):
        raise ValueError(f"无法标记第 {row_number} 行：行号超出表格范围")

    row = rows[row_index]
    if row_is_completed(row):
        return

    row.append(COMPLETED_MARK)
    write_csv_rows(table_path, rows)


def read_batch_items(table_path: str) -> BatchReadResult:
    article_columns = ("文章URL", "文章链接", "article_url", "article url", "url")
    image_columns = ("图片链接", "图片URL", "image_url", "image url", "image")

    rows = read_csv_rows(table_path)

    if not rows:
        return BatchReadResult(items=[], skipped_completed=0, data_rows=0)

    headers = rows[0]
    article_index = find_column_index(headers, article_columns)
    image_index = find_column_index(headers, image_columns)
    has_header = article_index is not None and image_index is not None

    if not has_header:
        article_index = 0
        image_index = 1

    items: list[BatchItem] = []
    data_rows = rows[1:] if has_header else rows
    row_offset = 2 if has_header else 1
    skipped_completed = 0
    data_row_count = 0

    for offset, row in enumerate(data_rows):
        row_number = row_offset + offset
        if not row or all(not cell.strip() for cell in row):
            continue
        data_row_count += 1
        if row_is_completed(row):
            skipped_completed += 1
            continue
        if len(row) <= max(article_index, image_index):
            raise ValueError(f"第 {row_number} 行缺少文章 URL 或图片链接")

        article_url = row[article_index].strip()
        image_url = row[image_index].strip()
        if not article_url or not image_url:
            raise ValueError(f"第 {row_number} 行文章 URL 或图片链接为空")

        items.append(
            BatchItem(
                row_number=row_number,
                article_url=article_url,
                image_url=image_url,
                article_id=extract_article_id(article_url),
            )
        )

    return BatchReadResult(
        items=items,
        skipped_completed=skipped_completed,
        data_rows=data_row_count,
    )


def resolve_batch_seed_url(item: BatchItem) -> str:
    image_url = item.image_url.strip()
    parsed_image = urlsplit(image_url)
    if parsed_image.scheme and parsed_image.netloc:
        return image_url

    parsed_article = urlsplit(item.article_url)
    if parsed_article.scheme and parsed_article.netloc:
        return urljoin(item.article_url, image_url)

    raise ValueError(f"第 {item.row_number} 行图片链接不是完整 URL，且文章 URL 也无法提供域名")


def batch_output_path(output_dir: str, article_id: str) -> str:
    return os.path.join(output_dir, f"{article_id}.json")


def run_probe(
        args: argparse.Namespace,
        printer: SafePrinter,
        article_url: str = "",
) -> ProbeSummary:
    validate_probe_args(args)
    seed = parse_seed_url(args.url)
    minute_increment_count = min(args.minute_increments, MAX_MINUTE - seed.minute)
    max_minute = seed.minute + minute_increment_count
    total = count_candidates(seed, minute_increment_count)
    retry_output_path = args.retry_output or default_retry_output_path(args.output)

    hits: list[Hit] = []
    retry_failures: list[RetryFailure] = []
    hits_lock = Lock()

    printer.line(f"[配置] 日期小时基础: {seed.date_hour_prefix}")
    printer.line(
        f"[配置] 起点: 分={seed.minute:02d}, 秒={seed.second:02d}, "
        f"小数={seed.fraction:0{FRACTION_DIGITS}d}"
    )
    printer.line("[配置] 样例链接: 会先单独检测，然后继续检测后续候选")
    printer.line(f"[配置] 分钟进位次数: {minute_increment_count}")
    if minute_increment_count > 0:
        printer.line(f"[配置] 分钟范围: {seed.minute:02d} -> {max_minute:02d}")
    else:
        printer.line(f"[配置] 分钟范围: 仅当前分钟 {seed.minute:02d}")
    printer.line("[配置] 秒范围: 当前秒起步，进位后 00 -> 59")
    printer.line(f"[配置] 小数范围: 当前小数起步，进位后 0000 -> {MAX_FRACTION:0{FRACTION_DIGITS}d}")
    printer.line(f"[配置] 候选数量上限: {total}")
    printer.line(f"[配置] 输出文件: {os.path.abspath(args.output)}")
    printer.line(f"[配置] 临时失败文件: {os.path.abspath(retry_output_path)}")

    checked = 0
    interrupted = False
    started_at = time.monotonic()
    dump_retry_failures(retry_output_path, retry_failures)

    try:
        seed_url = build_url(seed, seed.minute, seed.second, seed.fraction)
        seed_result = detect_url(
            seed_url,
            seed.minute,
            seed.second,
            seed.fraction,
            args,
            printer,
        )
        checked += 1
        with hits_lock:
            store_detection_result(
                seed_result,
                hits,
                retry_failures,
                args.output,
                retry_output_path,
            )

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            candidates = iter_candidates(
                seed,
                minute_increment_count,
                include_seed=False,
            )
            pending = set()
            exhausted = False
            max_pending = args.workers * 4

            while pending or not exhausted:
                while not exhausted and len(pending) < max_pending:
                    try:
                        url, minute, second, fraction = next(candidates)
                    except StopIteration:
                        exhausted = True
                        break
                    pending.add(
                        executor.submit(
                            detect_url,
                            url,
                            minute,
                            second,
                            fraction,
                            args,
                            printer,
                        )
                    )

                if not pending:
                    break

                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    checked += 1
                    try:
                        result = future.result()
                    except Exception as exc:
                        printer.line(f"[ERR] worker failed -> {exc}")
                        result = DetectionResult(hit=None, retry_failure=None)

                    with hits_lock:
                        store_detection_result(
                            result,
                            hits,
                            retry_failures,
                            args.output,
                            retry_output_path,
                        )

                    if checked % 1000 == 0:
                        elapsed = max(time.monotonic() - started_at, 0.001)
                        printer.line(
                            f"[进度] checked={checked}/{total}, "
                            f"found={len(hits)}, "
                            f"retry_failed={len(retry_failures)}, "
                            f"rate={checked / elapsed:.2f}/s"
                        )
    except KeyboardInterrupt:
        interrupted = True
        printer.line("[中断] 收到 Ctrl+C，正在保存已发现结果...")
    finally:
        dump_hits(args.output, hits, article_url=article_url, seed_url=args.url)
        dump_retry_failures(retry_output_path, retry_failures)

    if not interrupted and retry_failures:
        retry_failures = load_retry_failures(retry_output_path)
        retry_failures = run_final_retries(
            retry_failures,
            args,
            printer,
            hits,
            args.output,
            retry_output_path,
        )

    elapsed = max(time.monotonic() - started_at, 0.001)
    summary = ProbeSummary(
        checked=checked,
        total=total,
        found=len(hits),
        retry_failed=len(retry_failures),
        elapsed_seconds=elapsed,
        interrupted=interrupted,
    )
    dump_hits(args.output, hits, summary=summary, article_url=article_url, seed_url=args.url)
    dump_retry_failures(retry_output_path, retry_failures)
    printer.line(summary.message())
    return summary


def run_batch(args: argparse.Namespace, table_path: str) -> int:
    printer = SafePrinter()
    try:
        validate_probe_args(args)
        batch_result = read_batch_items(table_path)
    except (OSError, ValueError, argparse.ArgumentTypeError) as exc:
        print(f"[配置错误] {exc}", file=sys.stderr)
        return 2

    items = batch_result.items
    if not items:
        if batch_result.data_rows and batch_result.skipped_completed == batch_result.data_rows:
            print(f"[批量完成] 所有数据行均已标记为 {COMPLETED_MARK}：{table_path}")
            return 0
        print(f"[配置错误] 批量表格没有可处理的数据：{table_path}", file=sys.stderr)
        return 2

    os.makedirs(args.batch_output_dir, exist_ok=True)
    printer.line(f"[批量] 表格: {os.path.abspath(table_path)}")
    printer.line(f"[批量] 输出目录: {os.path.abspath(args.batch_output_dir)}")
    printer.line(
        f"[批量] 数据行: {batch_result.data_rows}, "
        f"已跳过: {batch_result.skipped_completed}, 待处理: {len(items)}"
    )

    failed_count = 0
    for index, item in enumerate(items, start=1):
        output_path = batch_output_path(args.batch_output_dir, item.article_id)
        printer.line(
            f"[批量] {index}/{len(items)} 行={item.row_number}, "
            f"id={item.article_id}, 输出={output_path}"
        )
        try:
            seed_url = resolve_batch_seed_url(item)
            probe_args = argparse.Namespace(**vars(args))
            probe_args.url = seed_url
            probe_args.output = output_path
            probe_args.retry_output = None
            summary = run_probe(probe_args, printer, article_url=item.article_url)
            if summary.interrupted:
                printer.line("[批量中断] 当前任务已保存，停止后续批量任务。")
                return 130
            mark_batch_row_completed(table_path, item.row_number)
            printer.line(f"[标记] 第 {item.row_number} 行 -> {COMPLETED_MARK}")
        except (ValueError, RuntimeError, OSError) as exc:
            failed_count += 1
            printer.line(f"[批量错误] 第 {item.row_number} 行 id={item.article_id}: {exc}")

    printer.line(f"[批量完成] total={len(items)}, failed={failed_count}")
    return 1 if failed_count else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="按 YYYYMMDDHH + 分 + 秒 + 四位小数 的时间进位规律枚举图片 URL，并保存 HTTP 200 结果。"
    )
    parser.add_argument("url", nargs="?", help="单条模式的样例图片 URL")
    parser.add_argument(
        "--batch-table",
        default=None,
        help=f"批量 CSV 表格路径，默认自动识别当前目录的 {DEFAULT_BATCH_TABLE}",
    )
    parser.add_argument(
        "--batch-output-dir",
        default=DEFAULT_BATCH_OUTPUT_DIR,
        help=f"批量 JSON 输出目录，默认 {DEFAULT_BATCH_OUTPUT_DIR}",
    )
    parser.add_argument(
        "--no-auto-batch",
        action="store_true",
        help=f"不自动读取当前目录的 {DEFAULT_BATCH_TABLE}",
    )
    parser.add_argument(
        "--minute-increments",
        type=int,
        default=DEFAULT_MINUTE_INCREMENT_COUNT,
        help=f"分钟最多进位次数，默认 {DEFAULT_MINUTE_INCREMENT_COUNT}；0 表示只检测当前分钟",
    )
    parser.add_argument("--workers", type=int, default=100, help="并发数，默认 50")
    parser.add_argument("--delay", type=float, default=0.05, help="每个请求前延迟秒数，默认 0.05")
    parser.add_argument("--timeout", type=float, default=5.0, help="请求超时时间，默认 5 秒")
    parser.add_argument("--retries", type=int, default=REQUEST_RETRIES, help=f"超时/临时错误重试次数，默认 {REQUEST_RETRIES}")
    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=RETRY_BACKOFF_SECONDS,
        help=f"重试退避基准秒数，默认 {RETRY_BACKOFF_SECONDS}",
    )
    parser.add_argument("--method", choices=("HEAD", "GET"), default="HEAD", help="检测方法，默认 HEAD")
    parser.add_argument("--fallback-get", action="store_true", help="HEAD 返回 403/405/501 时用 GET 重试")
    parser.add_argument("--quiet-404", action="store_true", help="不输出 404 日志；默认输出每个候选 URL 的状态码")
    parser.add_argument("--log-all", action="store_true", help="兼容旧参数；当前默认已经输出所有状态码")
    parser.add_argument("--output", default="found_200.json", help="单条模式 200 结果 JSON，默认 found_200.json")
    parser.add_argument("--retry-output", default=None, help="单条模式临时失败 JSON，默认跟随 output 命名")
    parser.add_argument(
        "--user-agent",
        default=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0"
        ),
        help="请求 User-Agent",
    )
    return parser


def validate_probe_args(args: argparse.Namespace) -> None:
    if args.minute_increments < 0:
        raise ValueError("minute-increments 不能为负数")
    if args.workers < 1:
        raise ValueError("workers 必须大于 0")
    if args.delay < 0:
        raise ValueError("delay 不能为负数")
    if args.timeout <= 0:
        raise ValueError("timeout 必须大于 0")
    if args.retries < 0:
        raise ValueError("retries 不能为负数")
    if args.retry_backoff < 0:
        raise ValueError("retry-backoff 不能为负数")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    batch_table = args.batch_table
    if (
            not batch_table
            and not args.url
            and not args.no_auto_batch
            and os.path.exists(DEFAULT_BATCH_TABLE)
    ):
        batch_table = DEFAULT_BATCH_TABLE

    if batch_table:
        return run_batch(args, batch_table)

    if not args.url:
        args.url = input("请输入样例图片 URL：\n").strip()

    try:
        run_probe(args, SafePrinter())
    except (ValueError, argparse.ArgumentTypeError) as exc:
        print(f"[配置错误] {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
