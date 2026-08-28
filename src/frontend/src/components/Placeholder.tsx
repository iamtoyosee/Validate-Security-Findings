export function Placeholder({ label }: { label: string }) {
  return (
    <div className="placeholder">
      <p className="placeholder-label">{label}</p>
      <p className="placeholder-status">Still Building — In progress</p>
    </div>
  );
}
