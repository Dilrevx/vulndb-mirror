import { useCallback, useEffect, useRef, useState } from "react";

const MIN_COL_WIDTH = 50;

export function useColumnResize(initialWidths: Record<string, number> = {}) {
    const [, forceUpdate] = useState(0);
    const widthsRef = useRef<Record<string, number>>({ ...initialWidths });
    const tableElRef = useRef<HTMLTableElement | null>(null);
    const resizing = useRef<{ key: string; startX: number; startWidth: number } | null>(null);

    const tableRef = useCallback((el: HTMLTableElement | null) => {
        tableElRef.current = el;
        if (el) {
            for (const [key, w] of Object.entries(widthsRef.current)) {
                el.style.setProperty(`--col-${key}`, `${w}px`);
            }
        }
    }, []);

    // Returns width style for a <th>. Falls back to widthsRef value so SSR/first render is correct.
    const thStyle = useCallback((key: string): React.CSSProperties => {
        const fallback = widthsRef.current[key];
        return { width: fallback !== undefined ? `var(--col-${key}, ${fallback}px)` : `var(--col-${key})` };
    }, []);

    const onResizeStart = useCallback((key: string) => (e: React.MouseEvent) => {
        e.preventDefault();
        e.stopPropagation();
        // Read actual rendered width from the <th> (parent of the resize handle)
        const th = (e.currentTarget as HTMLElement).parentElement;
        const startWidth = th ? th.getBoundingClientRect().width : (widthsRef.current[key] ?? 150);
        widthsRef.current[key] = startWidth;
        tableElRef.current?.style.setProperty(`--col-${key}`, `${startWidth}px`);
        resizing.current = { key, startX: e.clientX, startWidth };
        document.body.style.cursor = "col-resize";
        document.body.style.userSelect = "none";
    }, []);

    useEffect(() => {
        const onMouseMove = (e: MouseEvent) => {
            if (!resizing.current) return;
            const { key, startX, startWidth } = resizing.current;
            const newWidth = Math.max(MIN_COL_WIDTH, startWidth + (e.clientX - startX));
            widthsRef.current[key] = newWidth;
            tableElRef.current?.style.setProperty(`--col-${key}`, `${newWidth}px`);
        };
        const onMouseUp = () => {
            if (!resizing.current) return;
            resizing.current = null;
            document.body.style.cursor = "";
            document.body.style.userSelect = "";
            forceUpdate((n) => n + 1);
        };
        document.addEventListener("mousemove", onMouseMove);
        document.addEventListener("mouseup", onMouseUp);
        return () => {
            document.removeEventListener("mousemove", onMouseMove);
            document.removeEventListener("mouseup", onMouseUp);
        };
    }, []);

    return { tableRef, thStyle, onResizeStart };
}
