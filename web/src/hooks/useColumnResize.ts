import { useCallback, useEffect, useRef, useState } from "react";

export function useColumnResize(initialWidths: Record<string, number> = {}) {
    const [widths, setWidths] = useState<Record<string, number>>(initialWidths);
    const [resizingKey, setResizingKey] = useState<string | null>(null);
    const resizing = useRef<{ key: string; startX: number; startWidth: number } | null>(null);
    const thRefs = useRef<Record<string, HTMLElement>>({});

    const ref = useCallback((key: string) => (el: HTMLElement | null) => {
        if (el) thRefs.current[key] = el;
    }, []);

    const style = useCallback(
        (key: string) => {
            const w = widths[key];
            return w ? { width: w, minWidth: w } : undefined;
        },
        [widths],
    );

    const onResizeStart = useCallback(
        (key: string) => (e: React.MouseEvent) => {
            e.preventDefault();
            e.stopPropagation();
            const el = thRefs.current[key];
            if (!el) return;
            const rect = el.getBoundingClientRect();
            resizing.current = { key, startX: e.clientX, startWidth: rect.width };
            setResizingKey(key);
        },
        [],
    );

    useEffect(() => {
        const onMouseMove = (e: MouseEvent) => {
            if (!resizing.current) return;
            const { key, startX, startWidth } = resizing.current;
            const delta = e.clientX - startX;
            const newWidth = Math.max(60, startWidth + delta);
            setWidths((prev) => {
                if (prev[key] === newWidth) return prev;
                return { ...prev, [key]: newWidth };
            });
        };
        const onMouseUp = () => {
            resizing.current = null;
            setResizingKey(null);
            document.body.style.cursor = "";
            document.body.style.userSelect = "";
        };
        document.addEventListener("mousemove", onMouseMove);
        document.addEventListener("mouseup", onMouseUp);
        return () => {
            document.removeEventListener("mousemove", onMouseMove);
            document.removeEventListener("mouseup", onMouseUp);
        };
    }, []);

    useEffect(() => {
        if (resizingKey) {
            document.body.style.cursor = "col-resize";
            document.body.style.userSelect = "none";
        }
    }, [resizingKey]);

    return { ref, style, onResizeStart, resizingKey };
}
