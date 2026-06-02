import { ChatBubble } from '../lib/chat-ui';

interface ChatMessage {
  role: 'user' | 'ai';
  text: string;
}

interface ChatSidebarProps {
  chatOpen: boolean;
  setChatOpen: (open: boolean) => void;
  chatLog: ChatMessage[];
  chatInput: string;
  setChatInput: (input: string) => void;
  chatBusy: boolean;
  askChat: (overrideMsg?: string) => Promise<void> | void;
}

export function ChatSidebar({
  chatOpen,
  setChatOpen,
  chatLog,
  chatInput,
  setChatInput,
  chatBusy,
  askChat,
}: ChatSidebarProps) {
  if (!chatOpen) return null;

  return (
    <div className="lg:col-span-3 lg:sticky lg:top-6 h-[calc(100vh-140px)] max-h-[680px] flex flex-col security-card p-4 space-y-4 animate-fadeIn">
      <div className="flex items-center justify-between border-b border-[var(--border)] pb-2 shrink-0">
        <span className="text-[12px] uppercase tracking-wider font-bold text-[var(--blue)]">AI security analyst</span>
        <button 
          type="button" 
          onClick={() => setChatOpen(false)} 
          className="text-[11px] text-[var(--muted)] hover:text-[var(--text)] bg-transparent border-0 cursor-pointer"
        >
          Close
        </button>
      </div>
      
      <div className="flex-1 overflow-y-auto space-y-4 pr-1 scrollbar-thin min-h-0 no-scrollbar">
        {chatLog.length === 0 && (
          <div className="space-y-4 py-8 flex flex-col items-center">
            <p className="text-[13px] text-[var(--muted)] text-center leading-relaxed">
              Ask about fraud risk, remediation, or evidence — powered by Gemini.
            </p>
            <div className="w-full space-y-2 px-2 pt-4">
              <p className="text-[11px] uppercase tracking-widest text-[var(--muted)] font-semibold mb-1">Suggested Prompts</p>
              {[
                "Is this APK safe to install?",
                "Explain the dynamic C2 network traces",
                "Show all high risk banking fraud signals"
              ].map((phrase, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => askChat(phrase)}
                  className="w-full text-left py-2.5 px-3 bg-[var(--surface-2)]/50 border border-[var(--border)] rounded-xl text-[12.5px] text-zinc-300 hover:text-[var(--blue)] hover:border-[var(--blue)]/40 hover:bg-[var(--surface-2)] transition-all duration-300 cursor-pointer block font-medium"
                >
                  ✦ {phrase}
                </button>
              ))}
            </div>
          </div>
        )}
        {chatLog.map((m, i) => (
          <ChatBubble key={i} role={m.role} text={m.text} />
        ))}
        {chatBusy && (
          <div className="flex gap-2 items-center text-[12px] text-[var(--muted)]">
            <span className="w-6 h-6 rounded-full bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center animate-pulse">✦</span>
            Gemini is thinking…
          </div>
        )}
      </div>
      
      <div className="space-y-2 shrink-0 pt-2 border-t border-[var(--border)]">
        <div className="flex gap-1.5">
          <input
            value={chatInput}
            onChange={(e) => setChatInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && askChat()}
            placeholder="Ask a question..."
            className="flex-1 h-10 px-3.5 rounded-full bg-[var(--surface-2)] border border-[var(--border)] text-[13px] text-[var(--text)] outline-none focus:border-[var(--blue)]/50 focus:shadow-[0_0_10px_rgba(59,130,246,0.15)] transition-all duration-300"
          />
          <button 
            type="button" 
            onClick={() => askChat()} 
            disabled={chatBusy} 
            className="h-10 px-4 rounded-full bg-[var(--blue)] text-[#0b0b0c] text-[13px] font-bold border-0 cursor-pointer disabled:opacity-50 hover:opacity-90 active:scale-95 transition-all duration-200"
          >
            Send
          </button>
        </div>
      </div>
    </div>
  );
}
