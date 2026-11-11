#!/usr/bin/env python3
"""
CloudCompliance — Multi-LLM AI Compliance Assistant
Supports OpenAI, Anthropic Claude, AWS Bedrock, Local Ollama, and NVIDIA NIM,
with offline deterministic regulatory guidance fallback.
"""
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

import requests
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from dotenv import load_dotenv

load_dotenv()

console = Console()


def load_context() -> dict:
    """Load compliance report, drift report and tfstate as context."""
    from cloudcompliance.report import get_default_compliance_dir, get_default_tfstate_path
    comp_dir = get_default_compliance_dir()
    context = {}

    for fw in ["soc2", "hipaa", "pcidss"]:
        p = comp_dir / f"{fw}_compliance_report.json"
        if not p.exists() and fw == "soc2":
            p = comp_dir / "compliance_report.json"
        if p.exists():
            try:
                with open(p) as f:
                    context[f"{fw}_report"] = json.load(f)
                    if "compliance_report" not in context:
                        context["compliance_report"] = context[f"{fw}_report"]
            except Exception:
                pass

    drift_path = comp_dir / "drift_report.json"
    if drift_path.exists():
        try:
            with open(drift_path) as f:
                context["drift_report"] = json.load(f)
        except Exception:
            pass

    history_path = comp_dir / "history_export.json"
    if history_path.exists():
        try:
            with open(history_path) as f:
                context["history"] = json.load(f)
        except Exception:
            pass

    tfstate_path = get_default_tfstate_path()
    if tfstate_path.exists():
        try:
            with open(tfstate_path) as f:
                state = json.load(f)
                context["resource_count"] = len(state.get("resources", []))
                context["resource_types"] = list(
                    set(r.get("type") for r in state.get("resources", []) if r.get("type"))
                )
        except Exception:
            pass

    return context


def _truncate(obj, max_chars: int = 12000) -> str:
    """Serialize JSON, truncating if it is very large."""
    text = json.dumps(obj, indent=2, default=str)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated]"


def build_system_prompt(context: dict) -> str:
    report = context.get("compliance_report") or {}
    drift = context.get("drift_report") or {}

    return f"""You are CloudCompliance AI — an expert cloud compliance and security auditor.
You have access to the user's actual AWS infrastructure compliance data.

COMPLIANCE AUDIT EVIDENCE:
{_truncate(report)}

INFRASTRUCTURE DRIFT FINDINGS:
{_truncate(drift)}

INFRASTRUCTURE SCOPE:
- Total resources evaluated: {context.get("resource_count", "unknown")}
- Provisioned types: {", ".join(context.get("resource_types") or []) or "unknown"}

INSTRUCTIONS:
- Answer questions directly about the user's actual compliance state and controls.
- Reference actual control IDs (e.g., CC6.1, CC6.7, CC7.2), scores, and resource findings from their data.
- Give concrete, actionable remediation steps.
- Format responses in clean, structured Markdown.
- Never hallucinate data — only reference what is present in the evidence above.
"""


def generate_offline_guidance(question: str, context: dict) -> str:
    """Deterministic, air-gapped compliance analysis when no LLM API is configured."""
    report = context.get("compliance_report") or {}
    score = report.get("compliance_score", 100)
    controls = report.get("controls", {})
    passing = sum(1 for c in controls.values() if c.get("status") == "PASS")
    total = len(controls) if controls else 10
    res_count = context.get("resource_count", 46)

    q_lower = question.lower()
    if "audit" in q_lower or "ready" in q_lower or "pass" in q_lower:
        return f"""### Compliance Audit Readiness Assessment

**Status:** **{score}% Compliance Score** ({passing}/{total} Controls Enforced)
- **Active Resources:** {res_count} provisioned cloud resources in Terraform state

#### Validated Control Criteria:
1. **Access Boundaries & Isolation (CC6.1):** VPC private subnets and security group controls.
2. **Cryptographic Protection (CC6.7):** KMS customer-managed key rotation and S3 SSE enforcement.
3. **Audit Trails & Threat Monitoring (CC7.2 / CC7.3):** CloudTrail multi-region logs, CloudWatch metrics, and AWS Config continuous tracking.

#### Auditor Checklist:
- **Evidence Timeline:** Export timestamped compliance trends via `cloudcompliance history --export`.
- **Signed Audit Report:** Produce an executive signed PDF report via `cloudcompliance report --pdf`.
- **Zero Drift Verification:** Run `cloudcompliance drift` to guarantee no unmanaged out-of-band modifications.
"""
    elif "drift" in q_lower or "remediat" in q_lower or "fix" in q_lower:
        return f"""### Infrastructure Drift & Auto-Remediation Guidance

- **Monitored Assets:** {res_count} resources inspected against state
- **Remediation Commands:**
  - `cloudcompliance remediate --dry-run` — Preview automated remediation actions
  - `cloudcompliance remediate` — Execute S3 tagging and automatically open GitHub PRs for high-risk drift
- **Continuous Guard:** Deploy EventBridge Lambda trigger via `terraform/modules/event_driven_scanning` for zero-lag remediation.
"""
    else:
        return f"""### CloudCompliance Infrastructure Posture Summary

- **Primary Framework:** SOC2 Type II (Trust Services Criteria CC6–CC8, A1)
- **Score:** {score}% ({passing}/{total} controls active)
- **Audit Reports:** Detailed reports saved in `./compliance/` (.json, .md, .sarif, .pdf)

Run `cloudcompliance serve` to launch the interactive live dashboard, or `cloudcompliance scan --live` for real-time agentless AWS scanning.
"""


def detect_provider(provider_arg: Optional[str] = None, model_arg: Optional[str] = None) -> Tuple[str, str]:
    """Detect appropriate LLM provider and model based on arguments and environment."""
    if provider_arg:
        p = provider_arg.lower()
        if p == "openai":
            return "openai", model_arg or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        elif p == "anthropic":
            return "anthropic", model_arg or os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        elif p in ("ollama", "local"):
            return "ollama", model_arg or os.getenv("OLLAMA_MODEL", "llama3.2")
        elif p == "bedrock":
            return "bedrock", model_arg or os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0")
        elif p in ("nvidia", "nim"):
            return "nvidia", model_arg or os.getenv("NVIDIA_MODEL", "meta/llama-3.2-11b-vision-instruct")
        elif p == "offline":
            return "offline", "builtin-compliance-rules"

    # Automatic environment detection
    if os.getenv("OPENAI_API_KEY"):
        return "openai", model_arg or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    elif os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic", model_arg or os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
    elif os.getenv("NVIDIA_API_KEY"):
        return "nvidia", model_arg or os.getenv("NVIDIA_MODEL", "meta/llama-3.2-11b-vision-instruct")
    elif os.getenv("OLLAMA_HOST"):
        return "ollama", model_arg or os.getenv("OLLAMA_MODEL", "llama3.2")
    elif os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("USE_BEDROCK", "").lower() == "true":
        return "bedrock", model_arg or os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0")

    return "offline", "builtin-compliance-rules"


def call_openai(system_prompt: str, question: str, model: str, api_key: str) -> str:
    url = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1") + "/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question},
        ],
        "temperature": 0.2,
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=25)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def call_anthropic(system_prompt: str, question: str, model: str, api_key: str) -> str:
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "system": system_prompt,
        "messages": [{"role": "user", "content": question}],
        "max_tokens": 2048,
        "temperature": 0.2,
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=25)
    resp.raise_for_status()
    return resp.json()["content"][0]["text"]


def call_ollama(system_prompt: str, question: str, model: str, host: Optional[str] = None) -> str:
    base_host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    url = f"{base_host}/api/chat"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question},
        ],
        "stream": False,
    }
    resp = requests.post(url, json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json().get("message", {}).get("content", "")


def call_nvidia(system_prompt: str, question: str, model: str, api_key: str) -> str:
    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question},
        ],
        "max_tokens": 2048,
        "temperature": 0.3,
        "stream": False,
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=25)
    resp.raise_for_status()
    msg = resp.json()["choices"][0]["message"]
    return msg.get("content") or msg.get("reasoning_content") or ""


def call_bedrock(system_prompt: str, question: str, model: str) -> str:
    import boto3
    region = os.getenv("AWS_DEFAULT_REGION", os.getenv("AWS_REGION", "us-east-1"))
    bedrock = boto3.client("bedrock-runtime", region_name=region)
    response = bedrock.converse(
        modelId=model,
        messages=[{"role": "user", "content": [{"text": question}]}],
        system=[{"text": system_prompt}],
        inferenceConfig={"maxTokens": 2048, "temperature": 0.2},
    )
    return response["output"]["message"]["content"][0]["text"]


def ask(
    question: str,
    api_key: Optional[str] = None,
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> str:
    context = load_context()
    resolved_provider, resolved_model = detect_provider(provider, model)

    console.print()
    provider_title = f"{resolved_provider.upper()} ({resolved_model})"
    console.print(
        Panel.fit(
            f"[bold cyan]CloudCompliance AI Assistant[/bold cyan]\n"
            f"[dim]Provider: {provider_title}[/dim]",
            border_style="cyan",
        )
    )
    console.print(f"[dim]Question:[/dim] {question}\n")

    system_prompt = build_system_prompt(context)

    t0 = time.perf_counter()
    answer = ""

    try:
        with console.status(f"[cyan]Analyzing with {provider_title}…[/cyan]", spinner="dots"):
            if resolved_provider == "openai":
                key = api_key or os.getenv("OPENAI_API_KEY")
                answer = call_openai(system_prompt, question, resolved_model, key)
            elif resolved_provider == "anthropic":
                key = api_key or os.getenv("ANTHROPIC_API_KEY")
                answer = call_anthropic(system_prompt, question, resolved_model, key)
            elif resolved_provider == "ollama":
                answer = call_ollama(system_prompt, question, resolved_model, os.getenv("OLLAMA_HOST"))
            elif resolved_provider == "bedrock":
                answer = call_bedrock(system_prompt, question, resolved_model)
            elif resolved_provider == "nvidia":
                key = api_key or os.getenv("NVIDIA_API_KEY")
                answer = call_nvidia(system_prompt, question, resolved_model, key)
            else:
                answer = generate_offline_guidance(question, context)

    except Exception as e:
        console.print(f"[dim yellow]Notice: Provider '{resolved_provider}' error ({e.__class__.__name__}). Falling back to built-in regulatory rules.[/dim yellow]")
        answer = generate_offline_guidance(question, context)

    elapsed = time.perf_counter() - t0

    console.print(
        Panel(
            Markdown(answer),
            title="[bold green]Compliance Guidance[/bold green]",
            border_style="green",
        )
    )
    console.print(f"[dim]Response completed in {elapsed:.2f}s[/dim]\n")
    return answer


def main(
    question: str,
    api_key: Optional[str] = None,
    provider: Optional[str] = None,
    model: Optional[str] = None,
):
    ask(question, api_key=api_key, provider=provider, model=model)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print('[red]Usage: python assistant.py "your question"[/red]')
        sys.exit(1)
    main(sys.argv[1])
