import { useEffect, useRef, useState } from "react";
import { copyText } from "../clipboard";

interface Props {
  text: string;
  /** Element whose text is selected when the Clipboard API is unavailable. */
  fallbackRef: React.RefObject<HTMLElement | null>;
  label?: string;
  /** Accessible name, e.g. "Copy subscription URL". */
  ariaLabel?: string;
}

export function CopyButton({ text, fallbackRef, label = "Copy", ariaLabel }: Props) {
  const [feedback, setFeedback] = useState("");
  const timer = useRef<number | undefined>(undefined);

  useEffect(
    () => () => {
      window.clearTimeout(timer.current);
    },
    [],
  );

  const onClick = async () => {
    const res = await copyText(text, fallbackRef.current);
    setFeedback(
      res === "copied"
        ? "Copied"
        : res === "selected"
          ? "Selected – copy manually"
          : "Copy failed",
    );
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      setFeedback("");
    }, 2500);
  };

  return (
    <span className="copy">
      <button
        type="button"
        className="btn btn--small"
        onClick={() => void onClick()}
        aria-label={ariaLabel ?? label}
      >
        {label}
      </button>
      <span className="copy__feedback" role="status" aria-live="polite">
        {feedback}
      </span>
    </span>
  );
}
