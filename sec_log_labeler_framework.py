import os
import re
from typing import Any

try:
    from llama_cpp import Llama
except Exception:
    Llama = None


class SecLogLabelerFramework:
    BINARY_MODEL_PATH = "/models/Qwen2.5-7B-Instruct-Q4_K_M.gguf"
    MULTI_MODEL_PATH = os.path.join("./models", "Qwen2.5-7B-Instruct-Q4_K_M.gguf")

    BINARY_SYSTEM_PROMPT = (
        "You are an expert security analyst log classification engine. Your task is to analyze "
        "the log and determine if it represents a security issue (output 1) or a normal event (output 0). "
        "Before reaching a conclusion, **break down the log's components step by step**, "
        "considering the threat level, and **explicitly justify the final decision**. Follow the provided EXAMPLES closely. "
        "Provide your detailed reasoning, and then put the ONLY classification digit "
        "(1 or 0) on a new line, immediately preceded by three asterisks (***)."
    )

    FEW_SHOT_EXAMPLES = """
# Example 1: Security (S=1) 
Log: "Skipping, withExcluded: false, tr.intent:Intent { act=android.intent.action.VIEW dat=file:///storage/emulated/0/Tencent/QQfile_recv/b.apk typ=application/vnd.android.package-archive flg=0x10800000 cmp=com.android.packageinstaller/.PackageInstallerActivity (has extras) }"
Reasoning: The log shows an attempt to view an APK file and shows program path, suggesting a potential application installation from an untrusted source and thus posing a security risk.
***1

# Example 2: Non-Security (NS=0)
Log: "animateCollapsePanels:flags=0, force=false, delayed=false, mExpandedVisible=false"
Reasoning: This log entry pertains to a UI animation event with no indication of security implications.
***0

# Example 3: Security (S=1) 
Log: "acquire lock=233570404, flags=0x1, tag=""View Lock"", name=com.android.systemui, ws=null, uid=10037, pid=2227"
Reasoning: The log indicates an attempt to acquire a lock on a system UI component, which could be part of a larger security-sensitive operation.
***1

# Example 4: Non-Security (NS=0) 
Log: "Error receiving packet on tree network, expecting type 57 instead of type 3 (softheader=00589370 90990003 00000002 00000000) PSR0=00001f01 PSR1=00000000 PRXF=00000002 PIXF=00000007"
Reasoning: This log entry pertains to a network packet error with no indication of security implications.
***0

# Example 5: Security (S=1)
Log: "session closed for user news"
Reasoning: The log indicates a session closure for a user and user name is shown, which could be part of a security-sensitive operation.
***1

# Example 6: Non-Security (NS=0) 
Log: "initUserPrivacy the userPrivacy is true"
Reasoning: This log entry pertains to user privacy settings being initialized, with no indication of security implications.
***0

# Example 7: Security (S=1)
Log: "ciod: Error creating node map from file /home/pakin1/sweep3d-2.2b/results/random1-8x32x32x2.map: Permission denied"
Reasoning: This log entry indicates a permission denial error when attempting to create a node map file and shows program path, which could be part of a security-sensitive operation.
***1

# Example 8: Non-Security (NS=0)
Log: "data TLB error interrupt"
Reasoning: This log entry pertains to a data TLB error interrupt, which is a hardware-related event with no indication of security implications.
***0

# Example 9: Security (NS=0)
Log: "10.11.21.140,10.11.10.1 "GET /openstack/2013-10-17/meta_data.json HTTP/1.1" status: 200 len: 967 time: 0.0032220"
Reasoning: This log entry indicates HTTP GET request which can lead to security implications.
***1

# Example 10: Non-Security (NS=0)
Log: "getTasks: caller 10111 does not hold REAL_GET_TASKS; limiting output"
Reasoning: This log entry pertains to a task retrieval operation with no indication of security implications.
***0
"""

    MULTI_SYSTEM_PROMPT = (
        "You are an expert security analyst. Analyze the log and determine the impact on 6 security attributes.\n"
        "For each attribute, output 1 if it applies, otherwise 0.\n\n"
        "DEFINITIONS:\n"
        "C (Confidentiality): Shows authorized data (uid, pid, IP addresses, file paths, user names, package names).\n"
        "I (Integrity): System/data unauthorized modification or file errors.\n"
        "N (Non-repudiation): Evidence that an event occurred so that the events or actions cannot be repudiated later.\n"
        "Ac (Accountability): Traceability to a specific entity (Address change).\n"
        "Au (Authenticity): Identity verification (Auth success/failure).\n"
        "R (Resistance): System stability under stress (Panics/Attacks).\n\n"
        "Output Format: Provide reasoning, then end with: ***[C:X, I:X, N:X, Ac:X, Au:X, R:X]"
    )

    MULTILABEL_EXAMPLES = """
# Example 1:
Log: "session closed for user news"
Reasoning: This involves a user name breach referring to Confidentiality. 
***[C:1, I:0, N:0, Ac:0, Au:0, R:0]

# Example 2:
Log: "Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2"
Reasoning: This log indicates an unauthorized access attempt and shown ip address, impacting Confidentiality and Authenticity.
***[C:1, I:0, N:0, Ac:0, Au:1, R:0]

# Example 3:
Log: "reverse mapping checking getaddrinfo for customer-187-141-143-180-sta.uninet-ide.com.mx [187.141.143.180] failed - POSSIBLE BREAK-IN ATTEMPT!"
Reasoning: This log indicates a potential break-in attempt and system resisting it, affecting Resistance.
***[C:0, I:0, N:0, Ac:0, Au:0, R:1]

# Example 4:
Log: "has detected an available network connection on network 10.128.0.0 via interface ee0"
Reasoning: This log indicates ip address which can be used for unauthorized access.
***[C:0, I:1, N:0, Ac:0, Au:0, R:0]

# Example 5:
Log: "userActivityNoUpdateLocked: eventTime=261849942, event=2, flags=0x0, uid=1000"
Reasoning: This log indicates a user activity event which can be traced back to the user.
***[C:0, I:0, N:0, Ac:1, Au:0, R:0]

# Example 6:
Log: "ServerFileSystem: An ServerFileSystem domain panic has occurred on storage442"
Reasoning: This log indicates a server file system issue that may impact data integrity and also indicates system resistance.
***[C:0, I:1, N:0, Ac:0, Au:0, R:1]

# Example 7:
Log: "authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net user=root"
Reasoning: This log indicates an authentication failure which can be traced back to the user indicating confidentiality and also system attempting to resist it.
***[C:1, I:0, N:0, Ac:0, Au:1, R:1]

# Example 8:
Log: "ciod: Error loading /home/draeger/testQboxhang-nozerobytebug-nosleepyescomm: invalid or missing program image, No such file or directory"
Reasoning: This log indicates a failure to load a program image, which may impact system integrity and shows the ip address indicating a confidentiality breach.
***[C:1, I:1, N:0, Ac:0, Au:0, R:0]

# Example 9:
Log: "acquire lock=233570404, flags=0x1, tag='View Lock', name=com.android.systemui, uid=10037, pid=2227"
Reasoning: Contains a UID (10037) and PID (2227) which are system identifiers (C:1). It involves a lock status change (I:1). It identifies a specific UID (Ac:1).
***[C:1, I:1, N:0, Ac:1, Au:0, R:0]

# Example 10: The "System Lock" 
Log: "acquire lock=233570404, name=com.android.systemui, uid=10037, pid=2227"
Reasoning: Contains a UID/PID and package name (C:1). It is a state change 'acquire lock' (I:1). It is a background system service, so no unique accountability (Ac:0).
***[C:1, I:1, N:0, Ac:0, Au:0, R:0]

# Example 11: The "Connection Start" 
Log: "connection from 211.72.151.162 at Wed Jul 6 18:00:56 2005"
Reasoning: Reveals an IP address (C:1). This is the start of an authentication session (Au:1).
***[C:1, I:0, N:0, Ac:0, Au:1, R:0]

# Example 12: The "Identity Change" 
Log: "Address change detected. Old: 10.0.0.1 New: 10.0.0.2"
Reasoning: Contains IPs (C:1). This is a traceable shift in network identity (Ac:1).
***[C:1, I:0, N:0, Ac:1, Au:0, R:0]
"""

    def __init__(self, model_path: str | None = None):
        self.model_path = model_path or self.MULTI_MODEL_PATH
        self._llm = None
        self._llm_error = None

    def _load_llm(self):
        if self._llm is not None or self._llm_error is not None:
            return
        if Llama is None:
            self._llm_error = "llama-cpp-python is not installed."
            return
        selected_model_path = self.model_path
        if self.model_path == self.MULTI_MODEL_PATH and os.path.exists(self.BINARY_MODEL_PATH):
            selected_model_path = self.BINARY_MODEL_PATH
        try:
            self._llm = Llama(
                model_path=selected_model_path,
                n_gpu_layers=-1,
                n_ctx=4096,
                verbose=False,
            )
        except Exception as exc:
            self._llm_error = f"Model load failed: {exc}"

    def _call_llm_binary(self, prompt: str) -> dict[str, Any]:
        self._load_llm()
        if self._llm is None:
            raise RuntimeError(self._llm_error or "LLM unavailable")
        return self._llm(
            prompt,
            max_tokens=1550,
            temperature=0.0,
            stop=["<|im_end|>", "<|im_start|>"],
        )

    def _call_llm_multi(self, prompt: str) -> dict[str, Any]:
        self._load_llm()
        if self._llm is None:
            raise RuntimeError(self._llm_error or "LLM unavailable")
        return self._llm(prompt, max_tokens=1000, temperature=0.0, stop=["<|im_end|>"])

    @staticmethod
    def _extract_text(llm_response: dict[str, Any]) -> str:
        try:
            return llm_response["choices"][0]["text"]
        except Exception:
            return ""

    def build_full_prompt_binary(self, log_entry: str) -> str:
        new_log_query = f'\n# Log to Classify\nLog: "{log_entry}"\nReasoning:'
        user_prompt = self.FEW_SHOT_EXAMPLES + new_log_query

        full_prompt = (
            f"<|im_start|>system\n{self.BINARY_SYSTEM_PROMPT}<|im_end|>\n"
            f"<|im_start|>user\n{user_prompt}<|im_end|>\n"
            f"<|im_start|>assistant\nReasoning:"
        )
        return full_prompt

    @staticmethod
    def extract_binary_label(llm_response_dict: dict[str, Any]) -> int:
        try:
            raw_text = llm_response_dict["choices"][0]["text"]
            match = re.search(r"\*\*\*\s*([01])", raw_text, re.DOTALL | re.IGNORECASE)

            if match:
                return int(match.group(1))

            match_fallback = re.search(r"([01])[^0-9]*$", raw_text[-100:])
            if match_fallback:
                return int(match_fallback.group(1))

            return 0
        except (KeyError, IndexError):
            return -2

    @staticmethod
    def _extract_reasoning(llm_response: dict[str, Any]) -> str:
        """Return the model explanation without its final machine-readable label."""
        text = SecLogLabelerFramework._extract_text(llm_response).strip()
        if "***" in text:
            text = text.rsplit("***", 1)[0].strip()
        return text or "The model returned a label without an explanation."

    @staticmethod
    def _fallback_reason(log_text: str, label_type: str) -> str:
        text = (log_text or "").lower()
        if label_type == "binary":
            matches = [
                token
                for token in ("failed", "invalid", "unauthorized", "denied", "attack", "break-in", "root", "sudo", "auth")
                if token in text
            ]
            if matches:
                return "Fallback rule matched security indicator(s): " + ", ".join(matches) + "."
            return "Fallback rule found no configured security indicators in this log."
        return (
            "These labels were generated by the keyword fallback because the local model "
            "was unavailable; they are not model-generated explanations."
        )

    def build_full_prompt_multi(self, log_entry: str) -> str:
        user_prompt = f'{self.MULTILABEL_EXAMPLES}\n# Log to Classify\nLog: "{log_entry}"\nReasoning:'
        return (
            f"<|im_start|>system\n{self.MULTI_SYSTEM_PROMPT}<|im_end|>\n"
            f"<|im_start|>user\n{user_prompt}<|im_end|>\n"
            f"<|im_start|>assistant\nReasoning:"
        )

    @staticmethod
    def extract_multilabels(llm_response_dict: dict[str, Any]) -> dict[str, int]:
        labels = {"C": 0, "I": 0, "N": 0, "Ac": 0, "Au": 0, "R": 0}
        try:
            raw_text = llm_response_dict["choices"][0]["text"]
            pattern = r"\*\*\*\[\s*C:\s*(\d),\s*I:\s*(\d),\s*N:\s*(\d),\s*Ac:\s*(\d),\s*Au:\s*(\d),\s*R:\s*(\d)\s*\]"
            match = re.search(pattern, raw_text)

            if match:
                vals = match.groups()
                keys = list(labels.keys())
                for i in range(6):
                    labels[keys[i]] = int(vals[i])
            else:
                mapping = {"C:": "C", "I:": "I", "N:": "N", "Ac:": "Ac", "Au:": "Au", "R:": "R"}
                for key, short_name in mapping.items():
                    found = re.search(rf"{key}\s*(\d)", raw_text)
                    if found:
                        labels[short_name] = int(found.group(1))
            return labels
        except Exception:
            return labels

    @staticmethod
    def _fallback_binary(log_text: str) -> int:
        text = (log_text or "").lower()
        security_tokens = [
            "failed",
            "invalid",
            "unauthorized",
            "denied",
            "attack",
            "break-in",
            "root",
            "sudo",
            "auth",
        ]
        return 1 if any(token in text for token in security_tokens) else 0

    @staticmethod
    def _fallback_multi(log_text: str) -> dict[str, int]:
        text = (log_text or "").lower()
        return {
            "C": int(any(k in text for k in ["uid", "pid", "ip", "user", "file", "path"])),
            "I": int(any(k in text for k in ["error", "lock", "denied", "modify", "invalid"])),
            "N": int(any(k in text for k in ["audit", "signed", "receipt", "recorded"])),
            "Ac": int(any(k in text for k in ["address change", "actor", "uid", "trace"])),
            "Au": int(any(k in text for k in ["auth", "password", "login", "token"])),
            "R": int(any(k in text for k in ["panic", "dos", "attack", "flood", "break-in"])),
        }

    def annotate_log(self, log_text: str) -> dict[str, Any]:
        log_text = (log_text or "").strip()
        if not log_text:
            return {
                "binary_label": 0,
                "binary_reasoning": "No log was provided, so no security assessment was made.",
                "multilabels": None,
                "multilabel_reasoning": None,
                "mode": "empty_input",
                "message": "No log provided.",
                "error": None,
            }

        try:
            binary_prompt = self.build_full_prompt_binary(log_text)
            binary_resp = self._call_llm_binary(binary_prompt)
            binary_label = self.extract_binary_label(binary_resp)
            binary_reasoning = self._extract_reasoning(binary_resp)
            mode = "llm"
            error = None
        except Exception as exc:
            binary_label = self._fallback_binary(log_text)
            binary_reasoning = self._fallback_reason(log_text, "binary")
            mode = "fallback"
            error = str(exc)

        multilabels = None
        multilabel_reasoning = None
        if binary_label == 1:
            if mode == "llm":
                try:
                    multi_prompt = self.build_full_prompt_multi(log_text)
                    multi_resp = self._call_llm_multi(multi_prompt)
                    multilabels = self.extract_multilabels(multi_resp)
                    multilabel_reasoning = self._extract_reasoning(multi_resp)
                except Exception:
                    multilabels = self._fallback_multi(log_text)
                    multilabel_reasoning = self._fallback_reason(log_text, "multi")
                    mode = "fallback"
            else:
                multilabels = self._fallback_multi(log_text)
                multilabel_reasoning = self._fallback_reason(log_text, "multi")

        return {
            "binary_label": binary_label,
            "binary_reasoning": binary_reasoning,
            "multilabels": multilabels,
            "multilabel_reasoning": multilabel_reasoning,
            "mode": mode,
            "error": error,
        }
