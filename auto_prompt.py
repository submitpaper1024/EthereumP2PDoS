#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import re
import argparse
import asyncio
import subprocess
from typing import Optional, List, Tuple

from claude_agent_sdk import (
    ClaudeSDKClient,
    ClaudeAgentOptions,
    AssistantMessage,
    TextBlock,
)
from claude_agent_sdk.types import ToolUseBlock, ToolResultBlock

# ------------------------
# Shell helpers
# ------------------------

def run_shell(cmd: Optional[str], cwd: str, timeout: Optional[int] = None) -> Tuple[int, str]:
    if not cmd:
        return 0, ""
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        return 124, f"[TIMEOUT] command exceeded {timeout}s\n" + (out or "")

def tail_text(s: str, n_lines: Optional[int]) -> str:
    if not n_lines or n_lines <= 0:
        return s
    lines = s.splitlines()
    return "\n".join(lines[-n_lines:])

def clamp_bytes(s: str, max_bytes: int) -> str:
    b = s.encode("utf-8")[:max_bytes]
    return b.decode("utf-8", errors="ignore")

def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()

# ------------------------
# Feedback construction
# ------------------------

def build_feedback(exit_code: int, logs: str, rule: str, success_regex: Optional[str],
                   test_cmd: str, max_bytes: int, tail_lines: Optional[int]) -> str:
    trimmed = tail_text(logs, tail_lines)
    trimmed = clamp_bytes(trimmed, max_bytes)
    is_pass = (exit_code == 0) if rule == "exit_code" else (re.search(success_regex or "", logs) is not None)
    pass_desc = "passed" if is_pass else "failed"

    criteria = ("- Passing criteria: **exit code == 0**"
                else f"- Passing criteria: **regex /{success_regex}/ matches**") if rule == "exit_code" \
               else f"- Passing criteria: **regex /{success_regex}/ matches**"
    return f"""You have just completed an implementation round and executed the test command:

- Test command: `{test_cmd}`
{criteria}
- Actual evaluation: **{pass_desc}** (exit={exit_code})

Here is the test output (already truncated as needed):

<TEST_LOGS>
{trimmed}
</TEST_LOGS>

Please:
1) Read the logs, locate the issues, and fix them (keep changes minimal and verifiable).
2) Only use the necessary tools (Read/Edit/Write/Grep/Glob/Bash), and run tools **sequentially**:
   wait for one tool to finish before starting the next; Bash commands must run in order, not in parallel.
3) Self-check locally (you may run make or the same test command). When you are **ready for me to run the official tests**,
   please output a line **on its own** in your natural language reply: READY_FOR_TEST
"""

# ------------------------
# Agent I/O
# ------------------------

async def drain_once(client: ClaudeSDKClient, verbose: bool = True):
    """Consume one response, print text/tool calls, return (used, text_concat)."""
    used = {"edit": False, "write": False, "bash": False}
    texts = []
    async for msg in client.receive_response():
        if isinstance(msg, AssistantMessage):
            for b in msg.content:
                if isinstance(b, TextBlock):
                    if b.text:
                        texts.append(b.text)
                        if verbose:
                            print(b.text)
                elif isinstance(b, ToolUseBlock):
                    name = (b.name or "").lower()
                    if verbose:
                        print(f"ToolUse: {b.name} args={getattr(b, 'input', None)}")
                    if name == "edit": used["edit"] = True
                    if name == "write": used["write"] = True
                    if name.startswith("bash"): used["bash"] = True
                elif isinstance(b, ToolResultBlock):
                    if verbose:
                        print(f"ToolResult: {getattr(b, 'name', '')} status={getattr(b, 'status', '')}")
    return used, "\n".join(texts)

async def run_once_with_resilience(
    make_client,            # callable -> ClaudeSDKClient
    client: ClaudeSDKClient,
    prompt: str,
    turns: int,
):
    
    client.options.max_turns = turns
    max_retries = 3
    delay = 3
    for attempt in range(1, max_retries + 1):
        try:
            await client.query(prompt)
            used, texts = await drain_once(client, verbose=True)
            return client, used, texts
        except Exception as e:
            msg = str(e).lower()
            if "tool use concurrency" in msg or "concurrency" in msg:
                print(f"Tool concurrency error (attempt {attempt}/{max_retries}) — backing off {delay}s and retrying…")
                await asyncio.sleep(delay)
                delay = min(delay * 2, 12)
                continue
            raise

    # Still failing: soft-restart the session (close old client and create a new one)
    try:
        await client.__aexit__(None, None, None)
    except Exception:
        pass
    print("Soft-restarting agent session due to persistent concurrency errors…")
    client = make_client()                  # ← create new instance (sync)
    await client.__aenter__()               # ← explicitly enter session
    # Final attempt
    await client.query(prompt)
    used, texts = await drain_once(client, verbose=True)
    return client, used, texts

# ------------------------
# Implementation phase (strictly wait for READY_FOR_TEST)
# ------------------------

async def implementation_until_ready(
    make_client,
    client: ClaudeSDKClient,
    first_prompt: str,
    per_turns: int,
    ready_token: str,
    max_pretest_iterations: int,
):
    """
    Only consider the implementation "ready" when ready_token appears in the text.
    If max_pretest_iterations is exceeded without seeing the token, return False.
    """
    print("==[Implement] Run initial implementation prompt==")
    client, _, texts = await run_once_with_resilience(make_client, client, first_prompt, per_turns)
    if ready_token and (ready_token in texts):
        print(f"Ready token detected: {ready_token}, entering test phase.")
        return client, True

    FORCE_CONTINUE_PROMPT = f"""Continue implementation work and run tools **sequentially** (do not start multiple tools at once; execute Bash commands one by one).
When you are **confident** that the implementation is complete and ready for me to run the test command,
please output a line **on its own** in your reply: {ready_token}"""

    for i in range(1, max_pretest_iterations + 1):
        print(f"==[Implement/Continue #{i}] Waiting for ready token: {ready_token}==")
        client, _, texts = await run_once_with_resilience(make_client, client, FORCE_CONTINUE_PROMPT, per_turns)
        if ready_token and (ready_token in texts):
            print(f"Ready token detected: {ready_token}, entering test phase.")
            return client, True

    print("Implementation phase reached the maximum number of iterations without receiving the ready token; will not enter test phase.")
    return client, False

# ------------------------
# Feedback
# ------------------------

def passed(exit_code: int, logs: str, rule: str, success_regex: Optional[str]) -> bool:
    if rule == "exit_code":
        return exit_code == 0
    return bool(success_regex and re.search(success_regex, logs))

# ------------------------
# Main flow
# ------------------------

async def main(
    project_dir: str,
    task_prompt_path: str,
    test_cmd: str,
    pre_test_cmd: Optional[str],
    post_test_cmd: Optional[str],
    test_timeout: Optional[int],
    max_iterations: int,
    per_iteration_turns: int,
    permission_mode: str,
    model: Optional[str],
    setting_sources: List[str],
    allowed_tools: List[str],
    success_by: str,
    success_regex: Optional[str],
    tail_lines: Optional[int],
    log_bytes: int,
    ready_token: str,
    max_pretest_iterations: int,
):
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise SystemExit("Please export the ANTHROPIC_API_KEY environment variable first.")
    if not os.path.isdir(project_dir):
        raise SystemExit(f"Project directory does not exist: {project_dir}")
    if not os.path.isfile(task_prompt_path):
        raise SystemExit(f"Task prompt file does not exist: {task_prompt_path}")

    task_prompt = read_text(task_prompt_path)

    # Strict whitelist (remove TodoWrite/Notes/Plan, etc.)
    safe_allowed = []
    for t in allowed_tools:
        tl = t.lower()
        if tl in {"todowrite", "todo", "plan", "notes"}:
            continue
        safe_allowed.append(t)
    if not safe_allowed:
        safe_allowed = ["Read", "Edit", "Write", "Grep", "Glob", "Bash"]

    def make_options():
        return ClaudeAgentOptions(
            cwd=project_dir,
            permission_mode=permission_mode,
            max_turns=per_iteration_turns,
            setting_sources=setting_sources,
            model=model or None,
            allowed_tools=safe_allowed,
        )

    # Factory: create a new client for soft restarts (returns instance synchronously)
    def make_client():
        return ClaudeSDKClient(options=make_options())

    # Open initial session (explicit enter)
    client = make_client()
    await client.__aenter__()

    try:
        # ① Implementation phase: strictly wait for the ready token
        client, ready = await implementation_until_ready(
            make_client=make_client,
            client=client,
            first_prompt=task_prompt,
            per_turns=per_iteration_turns,
            ready_token=ready_token,
            max_pretest_iterations=max_pretest_iterations,
        )
        if not ready:
            raise SystemExit(2)

        # ② Test loop
        for i in range(1, max_iterations + 1):
            print(f"\n==[Tests #{i}] Running custom tests==")
            if pre_test_cmd:
                print(f"[pre-test] {pre_test_cmd}")
                c, o = run_shell(pre_test_cmd, cwd=project_dir, timeout=test_timeout)
                print(o)
                if c != 0:
                    print(f"[pre-test failed] exit code: {c}, going directly into feedback and fix phase…")

            code, logs = run_shell(test_cmd, cwd=project_dir, timeout=test_timeout)
            print(f"[test exit] {code}")
            print("[log preview]\n" + tail_text(logs, 800))

            if passed(code, logs, success_by, success_regex):
                print("Tests meet the passing criteria. Done.")
                if post_test_cmd:
                    print(f"[post-test] {post_test_cmd}")
                    pc, po = run_shell(post_test_cmd, cwd=project_dir, timeout=test_timeout)
                    print(po)
                break

            # ③ On failure → build feedback → go back to implementation phase (wait for ready token again)
            print(f"==[Iteration {i}] Build feedback → implementation phase (waiting for {ready_token})==")
            feedback_prompt = build_feedback(
                exit_code=code,
                logs=logs,
                rule=success_by,
                success_regex=success_regex,
                test_cmd=test_cmd,
                max_bytes=log_bytes,
                tail_lines=tail_lines,
            )
            client, ready = await implementation_until_ready(
                make_client=make_client,
                client=client,
                first_prompt=feedback_prompt,
                per_turns=per_iteration_turns,
                ready_token=ready_token,
                max_pretest_iterations=max_pretest_iterations,
            )
            if not ready:
                print("After feedback, implementation phase still did not produce the ready token; stopping.")
                raise SystemExit(3)
        else:
            print("Reached the maximum number of test iterations and still did not meet the passing criteria. Please inspect manually.")
    finally:
        try:
            await client.__aexit__(None, None, None)
        except Exception:
            pass

# ------------------------
# CLI
# ------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Claude Code auto-refactor (concurrency-resilient & only tests after explicit ready token)"
    )
    ap.add_argument("--project", required=True)
    ap.add_argument("--task-prompt", required=True)
    ap.add_argument("--test-cmd", required=True)
    ap.add_argument("--pre-test", default=None)
    ap.add_argument("--post-test", default=None)
    ap.add_argument("--test-timeout", type=int, default=None)
    ap.add_argument("--max-iterations", type=int, default=3)
    ap.add_argument("--per-iteration-turns", type=int, default=6)
    ap.add_argument("--permission-mode", default="acceptEdits")
    ap.add_argument("--model", default=None)
    ap.add_argument("--setting-sources", default="project")
    ap.add_argument("--allowed-tools", default="Read,Edit,Write,Grep,Glob,Bash")
    ap.add_argument("--success-by", choices=["exit_code", "regex"], default="exit_code")
    ap.add_argument("--success-regex", default=None)
    ap.add_argument("--tail-lines", type=int, default=1200)
    ap.add_argument("--log-bytes", type=int, default=200000)
    ap.add_argument(
        "--ready-token",
        default="READY_FOR_TEST",
        help="Token that the agent must output when implementation is complete and ready to be tested",
    )
    ap.add_argument(
        "--max-pretest-iterations",
        type=int,
        default=20,
        help="Maximum number of implementation iterations before tests; exceeded → exit without running tests",
    )
    args = ap.parse_args()

    setting_sources = [s.strip() for s in args.setting_sources.split(",") if s.strip()]
    allowed_tools = [s.strip() for s in args.allowed_tools.split(",") if s.strip()]

    asyncio.run(main(
        project_dir=os.path.abspath(args.project),
        task_prompt_path=args.task_prompt,
        test_cmd=args.test_cmd,
        pre_test_cmd=args.pre_test,
        post_test_cmd=args.post_test,
        test_timeout=args.test_timeout,
        max_iterations=args.max_iterations,
        per_iteration_turns=args.per_iteration_turns,
        permission_mode=args.permission_mode,
        model=args.model,
        setting_sources=setting_sources,
        allowed_tools=allowed_tools,
        success_by=args.success_by,
        success_regex=args.success_regex,
        tail_lines=args.tail_lines,
        log_bytes=args.log_bytes,
        ready_token=args.ready_token,
        max_pretest_iterations=args.max_pretest_iterations,
    ))
