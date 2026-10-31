import { useEffect, useId, useRef, useState } from "react";
import { MAX_REASON_LENGTH } from "../api";

interface Props {
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
  withReason?: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}

/** Modal confirmation using the native <dialog> element (focus trap + Esc for free). */
export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel,
  danger = false,
  withReason = false,
  onConfirm,
  onCancel,
}: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const [reason, setReason] = useState("");
  const titleId = useId();
  const descId = useId();
  const reasonId = useId();

  useEffect(() => {
    const d = ref.current;
    if (d === null) return;
    if (open && !d.open) {
      d.showModal();
    } else if (!open && d.open) {
      d.close();
    }
  }, [open]);

  const tooLong = reason.length > MAX_REASON_LENGTH;

  return (
    <dialog
      ref={ref}
      className="dialog"
      aria-labelledby={titleId}
      aria-describedby={descId}
      onCancel={(e) => {
        e.preventDefault();
        setReason("");
        onCancel();
      }}
    >
      <form
        method="dialog"
        className="dialog__form"
        onSubmit={(e) => {
          e.preventDefault();
          if (tooLong) return;
          const r = reason;
          setReason("");
          onConfirm(r);
        }}
      >
        <h2 id={titleId} className="dialog__title">
          {title}
        </h2>
        <p id={descId}>{message}</p>
        {withReason && (
          <div className="field">
            <label htmlFor={reasonId}>Reason (optional)</label>
            <input
              id={reasonId}
              type="text"
              value={reason}
              maxLength={MAX_REASON_LENGTH}
              autoComplete="off"
              onChange={(e) => {
                setReason(e.target.value);
              }}
            />
            <span className="field__hint">
              {reason.length}/{MAX_REASON_LENGTH}
            </span>
          </div>
        )}
        <div className="dialog__actions">
          <button
            type="button"
            className="btn"
            onClick={() => {
              setReason("");
              onCancel();
            }}
          >
            Cancel
          </button>
          <button
            type="submit"
            className={danger ? "btn btn--danger" : "btn btn--primary"}
            disabled={tooLong}
          >
            {confirmLabel}
          </button>
        </div>
      </form>
    </dialog>
  );
}
