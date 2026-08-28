import { useEffect, useRef, useState } from "react";

interface UploadPanelProps {
  onScan: (files: File[]) => void;
  loading: boolean;
}

// `webkitdirectory` has no React prop / TS type, so it's set imperatively via ref.
export function UploadPanel({ onScan, loading }: UploadPanelProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [selectedCount, setSelectedCount] = useState(0);
  const [folderName, setFolderName] = useState<string | null>(null);

  useEffect(() => {
    inputRef.current?.setAttribute("webkitdirectory", "");
    inputRef.current?.setAttribute("directory", "");
  }, []);

  const handleChange = () => {
    const files = inputRef.current?.files;
    setSelectedCount(files?.length ?? 0);
    const firstPath = files?.[0]?.webkitRelativePath;
    setFolderName(firstPath ? firstPath.split("/")[0] : null);
  };

  const handleScan = () => {
    const files = inputRef.current?.files;
    if (!files || files.length === 0) return;
    onScan(Array.from(files));
  };

  return (
    <div className="upload-panel">
      <input
        ref={inputRef}
        type="file"
        multiple
        hidden
        onChange={handleChange}
      />
      <button
        type="button"
        onClick={() => inputRef.current?.click()}
        disabled={loading}
      >
        Choose folder
      </button>
      <span className="upload-status">
        {folderName
          ? `${folderName} (${selectedCount} file${selectedCount === 1 ? "" : "s"})`
          : "No folder selected"}
      </span>
      <button
        type="button"
        className="scan-button"
        onClick={handleScan}
        disabled={loading || selectedCount === 0}
      >
        {loading ? "Scanning…" : "Scan"}
      </button>
    </div>
  );
}
