import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

export interface CreatableSelectOption {
  value: string;
  label?: string;
  description?: string;
}

export interface CreatableSelectBulkOption {
  label: string;
  description?: string;
  values: string[];
}

interface CreatableSelectProps {
  values: string[];
  onChange: (values: string[]) => void;
  options?: CreatableSelectOption[];
  bulkOptions?: CreatableSelectBulkOption[];
  placeholder?: string;
}

function getVisibleOptions(options: CreatableSelectOption[], values: string[], query: string) {
  const q = query.trim().toLowerCase();
  const filtered = q
    ? options.filter((o) => o.value.toLowerCase().includes(q) || o.label?.toLowerCase().includes(q) || o.description?.toLowerCase().includes(q))
    : options;
  return filtered.map((option) => ({ ...option, selected: values.includes(option.value) }));
}

export default function CreatableSelect({ values, onChange, options = [], bulkOptions = [], placeholder }: CreatableSelectProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [highlighted, setHighlighted] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const selectedValuesRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const positionFrameRef = useRef<number | null>(null);
  const keyboardNavigationRef = useRef(false);
  const listboxId = useId();
  const [pos, setPos] = useState({ top: 0, left: 0, width: 0, maxHeight: 256 });

  const q = query.trim().toLowerCase();
  const filteredBulkOptions = q
    ? bulkOptions.filter((option) => option.label.toLowerCase().includes(q) || option.description?.toLowerCase().includes(q))
    : bulkOptions;
  const filtered = getVisibleOptions(options, values, query);
  const exactMatch = options.some((o) => o.value.toLowerCase() === q)
    || bulkOptions.some((option) => option.label.toLowerCase() === q)
    || values.some((v) => v.toLowerCase() === q);
  const showCreate = q && !exactMatch;

  const items: {
    type: "bulk" | "option" | "create";
    bulkOption?: CreatableSelectBulkOption;
    option?: CreatableSelectOption & { selected: boolean };
    createValue?: string;
  }[] = [
    ...filteredBulkOptions.map((bulkOption) => ({ type: "bulk" as const, bulkOption })),
    ...filtered.map((o) => ({ type: "option" as const, option: o })),
    ...(showCreate ? [{ type: "create" as const, createValue: query.trim() }] : []),
  ];
  const menuOpen = open && items.length > 0;
  const activeOptionId = menuOpen ? `${listboxId}-option-${Math.min(highlighted, items.length - 1)}` : undefined;

  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (
        listRef.current && !listRef.current.contains(e.target as Node) &&
        wrapperRef.current && !wrapperRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    const handleViewportChange = () => schedulePositionUpdate();
    window.addEventListener("resize", handleViewportChange);
    window.addEventListener("scroll", handleViewportChange, { capture: true, passive: true });
    return () => {
      document.removeEventListener("mousedown", handleClick);
      window.removeEventListener("resize", handleViewportChange);
      window.removeEventListener("scroll", handleViewportChange, true);
      if (positionFrameRef.current !== null) {
        window.cancelAnimationFrame(positionFrameRef.current);
        positionFrameRef.current = null;
      }
    };
  }, [open]);

  function schedulePositionUpdate() {
    if (positionFrameRef.current !== null) return;
    positionFrameRef.current = window.requestAnimationFrame(() => {
      positionFrameRef.current = null;
      updatePosition();
    });
  }

  function updatePosition() {
    if (wrapperRef.current) {
      const rect = wrapperRef.current.getBoundingClientRect();
      const gap = 4;
      const maxMenuHeight = 256;
      const menuHeight = Math.min(listRef.current?.scrollHeight ?? maxMenuHeight, maxMenuHeight);
      const spaceBelow = window.innerHeight - rect.bottom - gap;
      const spaceAbove = rect.top - gap;
      const openAbove = spaceBelow < menuHeight && spaceAbove > spaceBelow;
      const availableHeight = Math.max(0, Math.min(maxMenuHeight, openAbove ? spaceAbove : spaceBelow));
      const visibleMenuHeight = Math.min(menuHeight, availableHeight);
      const nextPos = {
        top: openAbove ? Math.max(gap, rect.top - visibleMenuHeight - gap) : rect.bottom + gap,
        left: rect.left,
        width: rect.width,
        maxHeight: availableHeight,
      };
      setPos((current) => (
        current.top === nextPos.top
        && current.left === nextPos.left
        && current.width === nextPos.width
        && current.maxHeight === nextPos.maxHeight
          ? current
          : nextPos
      ));
    }
  }

  useLayoutEffect(() => {
    if (selectedValuesRef.current) selectedValuesRef.current.scrollTop = selectedValuesRef.current.scrollHeight;
    if (open) updatePosition();
  }, [open, values, query]);

  useLayoutEffect(() => {
    if (!keyboardNavigationRef.current) return;
    keyboardNavigationRef.current = false;
    const list = listRef.current;
    if (!menuOpen || !activeOptionId || !list || list.clientHeight <= 0) return;
    const activeOption = document.getElementById(activeOptionId);
    if (!activeOption || !list.contains(activeOption)) return;

    const optionTop = activeOption.offsetTop;
    const optionBottom = optionTop + activeOption.offsetHeight;
    const visibleTop = list.scrollTop;
    const visibleBottom = visibleTop + list.clientHeight;
    if (optionTop < visibleTop) {
      list.scrollTop = optionTop;
    } else if (optionBottom > visibleBottom) {
      list.scrollTop = optionBottom - list.clientHeight;
    }
  }, [activeOptionId, items.length, menuOpen, query]);

  function show() {
    keyboardNavigationRef.current = false;
    updatePosition();
    setHighlighted(0);
    setOpen(true);
  }

  function addValue(v: string) {
    if (!v || values.includes(v)) return;
    onChange([...values, v]);
    setQuery("");
    setHighlighted(0);
  }

  function removeValue(v: string) {
    onChange(values.filter((x) => x !== v));
  }

  function toggleOption(v: string) {
    if (values.includes(v)) {
      removeValue(v);
    } else {
      addValue(v);
    }
  }

  function toggleBulkOption(option: CreatableSelectBulkOption) {
    const allSelected = option.values.length > 0 && option.values.every((value) => values.includes(value));
    if (allSelected) {
      const bundleValues = new Set(option.values);
      onChange(values.filter((value) => !bundleValues.has(value)));
    } else {
      onChange([...values, ...option.values.filter((value) => !values.includes(value))]);
    }
    setQuery("");
    setHighlighted(0);
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Backspace" && !query && values.length > 0) {
      onChange(values.slice(0, -1));
      return;
    }
    if (!open || items.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      keyboardNavigationRef.current = true;
      setHighlighted((h) => (h + 1) % items.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      keyboardNavigationRef.current = true;
      setHighlighted((h) => (h - 1 + items.length) % items.length);
    } else if (e.key === "Enter") {
      e.preventDefault();
      keyboardNavigationRef.current = true;
      const item = items[Math.min(highlighted, items.length - 1)];
      if (item.type === "create" && item.createValue) {
        addValue(item.createValue);
      } else if (item.type === "bulk" && item.bulkOption) {
        toggleBulkOption(item.bulkOption);
      } else if (item.type === "option" && item.option) {
        toggleOption(item.option.value);
      }
    } else if (e.key === "Escape") {
      e.stopPropagation();
      setOpen(false);
    }
  }

  return (
    <div ref={wrapperRef} className="relative">
      <div
        className={`flex items-center gap-1.5 w-full min-h-[46px] px-3 py-2 bg-surface-raised border rounded-lg text-sm transition-colors cursor-text ${open ? "border-border-focus shadow-[0_0_0_3px_var(--color-primary-ring)]" : "border-border"}`}
        onClick={() => { inputRef.current?.focus(); }}
      >
        <div ref={selectedValuesRef} data-selected-values className="flex flex-wrap items-center gap-1.5 flex-1 min-w-0 max-h-40 overflow-y-auto">
          {values.map((v) => {
            const opt = options.find((o) => o.value === v);
            const label = opt?.label || v;
            return (
              <span key={v} className="inline-flex items-start gap-1 bg-primary/10 text-primary border border-primary/20 text-xs font-medium rounded-md px-2 py-1 max-w-full">
                <span title={v} className="min-w-0 whitespace-normal break-all leading-4">{label}</span>
                <button
                  type="button"
                  tabIndex={-1}
                  aria-label={`Remove ${label}`}
                  onClick={(e) => { e.stopPropagation(); removeValue(v); }}
                  className="flex-shrink-0 mt-0.5 text-text-dim hover:text-text transition-colors"
                >
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                </button>
              </span>
            );
          })}
          <input
            ref={inputRef}
            role="combobox"
            aria-label={placeholder || "Select options"}
            aria-expanded={menuOpen}
            aria-controls={listboxId}
            aria-haspopup="listbox"
            aria-autocomplete="list"
            aria-activedescendant={activeOptionId}
            value={query}
            placeholder={values.length === 0 ? placeholder : undefined}
            onChange={(e) => { setQuery(e.target.value); setHighlighted(0); show(); }}
            onFocus={show}
            onKeyDown={handleKeyDown}
            autoComplete="off"
            className="flex-1 min-w-[80px] bg-transparent outline-none text-text text-sm py-1"
          />
        </div>
        <div className="flex items-center gap-1 flex-shrink-0 self-start mt-2">
          {values.length > 0 && (
            <button
              type="button"
              tabIndex={-1}
              aria-label="Clear all"
              onMouseDown={(e) => { e.preventDefault(); onChange([]); setQuery(""); }}
              className="text-text-dim hover:text-text transition-colors"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
            </button>
          )}
          <button
            type="button"
            tabIndex={-1}
            aria-label="Show suggestions"
            onMouseDown={(e) => {
              e.preventDefault();
              if (open) { setOpen(false); } else { inputRef.current?.focus(); show(); }
            }}
            className="w-4 h-4 text-text-muted hover:text-text transition-colors"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="6 9 12 15 18 9" />
            </svg>
          </button>
        </div>
      </div>
      {open && items.length > 0 &&
        createPortal(
          <div
            ref={listRef}
            id={listboxId}
            role="listbox"
            aria-multiselectable="true"
            className="fixed z-50 bg-surface border border-border rounded-lg shadow-[0_4px_16px_rgba(0,0,0,0.12)] py-1 overflow-y-auto"
            style={{ top: pos.top, left: pos.left, width: pos.width, maxHeight: pos.maxHeight, scrollbarWidth: "thin", scrollbarColor: "var(--color-border) var(--color-surface)" }}
          >
            {items.map((item, i) => {
              if (item.type === "bulk") {
                const bulkOption = item.bulkOption!;
                const selected = bulkOption.values.length > 0 && bulkOption.values.every((value) => values.includes(value));
                return (
                  <button
                    key={`__bulk__${bulkOption.label}`}
                    id={`${listboxId}-option-${i}`}
                    type="button"
                    tabIndex={-1}
                    role="option"
                    aria-selected={selected}
                    onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
                    onClick={() => { keyboardNavigationRef.current = false; toggleBulkOption(bulkOption); }}
                    onMouseEnter={() => { keyboardNavigationRef.current = false; setHighlighted(i); }}
                    className={`w-full text-left px-4 py-2.5 transition-colors flex items-center justify-between border-b border-border ${i === highlighted ? "bg-bg" : ""}`}
                  >
                    <div className="min-w-0 flex-1">
                      <span className="block text-sm font-semibold text-text">{bulkOption.label}</span>
                      {bulkOption.description && <span className="block text-xs text-text-dim whitespace-normal">{bulkOption.description}</span>}
                    </div>
                    {selected && (
                      <svg className="w-4 h-4 flex-shrink-0 text-primary ml-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
                    )}
                  </button>
                );
              }
              if (item.type === "create") {
                return (
                  <button
                    key="__create__"
                    id={`${listboxId}-option-${i}`}
                    type="button"
                    tabIndex={-1}
                    role="option"
                    aria-selected="false"
                    onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
                    onClick={() => { keyboardNavigationRef.current = false; addValue(item.createValue!); }}
                    onMouseEnter={() => { keyboardNavigationRef.current = false; setHighlighted(i); }}
                    className={`w-full text-left px-4 py-2.5 transition-colors border-t border-border ${i === highlighted ? "bg-bg" : ""}`}
                  >
                    <span className="text-sm text-primary">Add "{item.createValue}"</span>
                  </button>
                );
              }
              const opt = item.option!;
              const selected = opt.selected;
              return (
                <button
                  key={opt.value}
                  id={`${listboxId}-option-${i}`}
                  type="button"
                  tabIndex={-1}
                  role="option"
                  aria-selected={selected}
                  onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
                  onClick={() => { keyboardNavigationRef.current = false; toggleOption(opt.value); }}
                  onMouseEnter={() => { keyboardNavigationRef.current = false; setHighlighted(i); }}
                  className={`w-full text-left px-4 py-2.5 transition-colors flex items-center justify-between ${i === highlighted ? "bg-bg" : ""}`}
                >
                  <div className="min-w-0 flex-1">
                    <span title={opt.value} className="block text-sm text-text whitespace-normal break-all">{opt.label || opt.value}</span>
                    {opt.description && <span className="block text-xs text-text-dim whitespace-normal">{opt.description}</span>}
                  </div>
                  {selected && (
                    <svg className="w-4 h-4 flex-shrink-0 text-primary ml-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
                  )}
                </button>
              );
            })}
          </div>,
          document.body
        )}
    </div>
  );
}
