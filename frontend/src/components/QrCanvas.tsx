import { useEffect, useRef, useState } from "react";
import QRCode from "qrcode";

interface Props {
  value: string;
  label: string;
}

/** Renders `value` as a QR code into a <canvas> (no inline styles, no data: URLs). */
export function QrCanvas({ value, label }: Props) {
  const ref = useRef<HTMLCanvasElement>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const canvas = ref.current;
    if (canvas === null) return undefined;
    let cancelled = false;
    QRCode.toCanvas(canvas, value, {
      errorCorrectionLevel: "M",
      margin: 2,
      width: 256,
      color: { dark: "#000000ff", light: "#ffffffff" },
    }).then(
      () => {
        if (!cancelled) setFailed(false);
      },
      () => {
        if (!cancelled) setFailed(true);
      },
    );
    return () => {
      cancelled = true;
      const ctx = canvas.getContext("2d");
      ctx?.clearRect(0, 0, canvas.width, canvas.height);
    };
  }, [value]);

  return (
    <div className="qr">
      <canvas ref={ref} className="qr__canvas" role="img" aria-label={label} />
      {failed && (
        <p className="error" role="alert">
          Could not render the QR code.
        </p>
      )}
    </div>
  );
}
