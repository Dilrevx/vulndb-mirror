import { useVirtualizer } from "@tanstack/react-virtual";
import { useRef } from "react";

export function useTableVirtualizer(count: number, estimateSize = 32) {
    const scrollRef = useRef<HTMLDivElement>(null);
    const virtualizer = useVirtualizer({
        count,
        getScrollElement: () => scrollRef.current,
        estimateSize: () => estimateSize,
        overscan: 5,
    });
    return { scrollRef, virtualizer };
}

export function useDynamicTableVirtualizer(count: number, estimateSize = 48) {
    const scrollRef = useRef<HTMLDivElement>(null);
    const virtualizer = useVirtualizer({
        count,
        getScrollElement: () => scrollRef.current,
        estimateSize: () => estimateSize,
        overscan: 3,
        measureElement:
            typeof window !== "undefined" && !navigator.userAgent.includes("Firefox")
                ? (el) => el.getBoundingClientRect().height
                : undefined,
    });
    return { scrollRef, virtualizer };
}
