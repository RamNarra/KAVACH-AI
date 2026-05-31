import re

with open('frontend/src/app/page.tsx', 'r') as f:
    text = f.read()

start_marker = "const renderCompletedState = () => {"
end_marker = "  const renderActiveScene = () => {"

start_index = text.find(start_marker)
end_index = text.find(end_marker)

if start_index == -1 or end_index == -1:
    print("Could not find boundaries")
    exit(1)

new_content = """const renderCompletedState = () => {
    if (!activeResult) return null;

    return (
      <div className="mx-auto w-full max-w-[1600px] px-6 py-6 relative z-10 select-text animate-fade-in pb-16">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            
            {/* Left Column */}
            <div className="space-y-6">
              <section className={cn('rounded-2xl p-6 sm:p-8 shadow-xl relative overflow-hidden transition-all duration-300', activeTheme.bg, activeTheme.border)}>
                <div className="absolute -right-32 -top-32 w-80 h-80 rounded-full bg-white/5 blur-[120px] pointer-events-none" />
                
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6 relative z-10">
                  <div className="select-none flex-1">
                    <p className={cn("text-[10px] font-extrabold font-mono tracking-widest uppercase", activeTheme.text)}>SANDBOX VERDICT</p>
                    <h2 className={cn('mt-2 text-4xl sm:text-5xl font-extrabold tracking-tight uppercase leading-none font-mono', activeTheme.text)}>
                      {activeTheme.statement}
                    </h2>
                    <div className="mt-5 space-y-1.5 font-mono text-xs text-zinc-300">
                      <p><span className="text-zinc-500">Target File:</span> {activeResult.filename}</p>
                      <p><span className="text-zinc-500">Package ID: </span> {activeResult.package_name || 'Not extracted'}</p>
                      <p><span className="text-zinc-500">SHA-256 ID: </span> <span className="break-all select-all font-semibold font-sans">{reportHash}</span></p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 border border-zinc-800 bg-black/60 p-5 rounded-xl shrink-0 select-none font-mono max-w-[150px] justify-center shadow-lg">
                    <div className="text-center w-full">
                      <span className="text-[10px] font-extrabold text-zinc-500 tracking-widest block mb-1 uppercase">Risk Index</span>
                      <span className={cn('text-6xl font-extrabold tracking-tighter leading-none', activeTheme.text)}>
                        {riskScore}
                      </span>
                      <span className="text-xs text-zinc-600 font-bold block mt-1">/ 100</span>
                    </div>
                  </div>
                </div>
              </section>

              <section className="rounded-2xl bg-black/40 p-6 shadow-xl relative border border-green-500/20">
                <h3 className="text-sm font-extrabold font-mono text-green-400 flex gap-2.5 items-center uppercase tracking-widest border-b border-green-500/20 pb-3 select-none">
                  <Sparkles className="w-5 h-5 glow-text-green" /> AI Synthesis Summary
                </h3>
                <div 
                  className="text-zinc-300 leading-relaxed text-sm select-text space-y-3 mt-4 font-mono"
                  dangerouslySetInnerHTML={{ __html: formatMarkdown(activeResult?.investigation_report?.summary || 'No narrative report synthesized.') }}
                />
              </section>

              <div className="pt-4">
                <button
                  type="button"
                  onClick={resetWorkspace}
                  className="w-full sm:w-auto px-8 py-4 bg-green-500 hover:bg-green-400 rounded-xl text-black font-extrabold uppercase tracking-widest transition-all cursor-pointer shadow-[0_0_20px_rgba(17,255,59,0.3)] hover:-translate-y-0.5 active:scale-[0.98] font-mono text-xs"
                >
                  [ SCAN NEW TARGET ]
                </button>
              </div>
            </div>

            {/* Right Column */}
            <div className="space-y-6">
              <section className="rounded-2xl bg-black/40 shadow-xl relative border border-green-500/20 h-full">
                <div className="p-6 border-b border-green-500/20">
                  <h3 className="text-sm font-extrabold font-mono text-green-400 flex gap-2.5 items-center uppercase tracking-widest select-none">
                    <Radar className="w-5 h-5 glow-text-green" /> Comprehensive AI Breakdown
                  </h3>
                </div>
                
                <div className="p-6 overflow-y-auto pr-4 scrollbar-thin select-text space-y-6 max-h-[85vh]">
                  
                  {activeResult?.investigation_report?.permissions_analysis && activeResult.investigation_report.permissions_analysis.length > 0 && (
                    <div className="space-y-3">
                      <h4 className="text-xs font-bold font-mono text-zinc-400 uppercase tracking-widest mb-4 flex items-center gap-2"><span className="w-2 h-2 bg-rose-500 rounded-sm"></span> Critical Permissions</h4>
                      {activeResult.investigation_report.permissions_analysis.map((perm, idx) => (
                        <div key={idx} className="border border-green-500/10 bg-black/60 p-4 rounded-xl space-y-2 relative overflow-hidden group hover:border-green-500/30 transition-colors">
                          <div className="flex items-start justify-between gap-3 font-mono border-b border-white/5 pb-2 mb-2">
                            <p className="text-xs font-bold text-zinc-200 break-all">{perm.permission}</p>
                            <span className="rounded border border-green-500/20 bg-green-500/10 px-2 py-0.5 text-[10px] font-bold text-green-400 shrink-0 select-none uppercase">
                              {perm.status}
                            </span>
                          </div>
                          <p className="text-xs text-zinc-400 leading-relaxed font-mono">{perm.description}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  {activeResult?.investigation_report?.suspicious_activities && activeResult.investigation_report.suspicious_activities.length > 0 && (
                    <div className="space-y-3 mt-8">
                      <h4 className="text-xs font-bold font-mono text-zinc-400 uppercase tracking-widest mb-4 flex items-center gap-2"><span className="w-2 h-2 bg-amber-500 rounded-sm"></span> Anomalous Behaviors</h4>
                      {activeResult.investigation_report.suspicious_activities.map((act, idx) => (
                        <div key={idx} className="border border-green-500/10 bg-black/60 p-4 rounded-xl space-y-2 relative overflow-hidden group hover:border-green-500/30 transition-colors">
                          <div className="flex items-start justify-between gap-3 font-mono border-b border-white/5 pb-2 mb-2">
                            <p className="text-xs font-bold text-zinc-200 break-all">{act.title}</p>
                            {act.severity && (
                              <span className="rounded border border-green-500/20 bg-green-500/10 px-2 py-0.5 text-[10px] font-bold text-green-400 shrink-0 select-none uppercase">
                                {act.severity}
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-zinc-400 leading-relaxed font-mono">{act.description}</p>
                          {act.file && <p className="text-[10px] text-zinc-500 font-mono tracking-widest uppercase mt-2 pt-2 border-t border-white/5">FILE: {act.file}</p>}
                        </div>
                      ))}
                    </div>
                  )}

                  {activeResult?.investigation_report?.code_vulnerabilities && activeResult.investigation_report.code_vulnerabilities.length > 0 && (
                    <div className="space-y-3 mt-8">
                      <h4 className="text-xs font-bold font-mono text-zinc-400 uppercase tracking-widest mb-4 flex items-center gap-2"><span className="w-2 h-2 bg-rose-600 rounded-sm"></span> Protocol Vulnerabilities</h4>
                      {activeResult.investigation_report.code_vulnerabilities.map((vuln, idx) => (
                        <div key={idx} className="border border-rose-500/20 bg-rose-950/10 p-4 rounded-xl space-y-2 relative overflow-hidden group hover:border-rose-500/40 transition-colors">
                          <div className="flex items-start justify-between gap-3 font-mono border-b border-rose-500/10 pb-2 mb-2">
                            <p className="text-xs font-bold text-rose-300 break-all">{vuln.title}</p>
                            {vuln.severity && (
                              <span className="rounded border border-rose-500/30 bg-rose-500/20 px-2 py-0.5 text-[10px] font-bold text-rose-400 shrink-0 select-none uppercase">
                                {vuln.severity}
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-zinc-400 leading-relaxed font-mono">{vuln.description}</p>
                          {vuln.file && <p className="text-[10px] text-rose-500/70 font-mono tracking-widest uppercase mt-2 pt-2 border-t border-rose-500/10">ENTRYPOINT: {vuln.file}</p>}
                        </div>
                      ))}
                    </div>
                  )}

                </div>
              </section>
            </div>
            
        </div>
      </div>
    );
  };

"""

# Overwrite colors globally as well
text = text[:start_index] + new_content + text[end_index:]
text = text.replace('emerald', 'green')
text = text.replace('sky', 'green')
text = text.replace('purple', 'green')
text = text.replace('text-green-500', 'text-[#11ff3b]')
text = text.replace('bg-green-500', 'bg-[#11ff3b]')
text = text.replace('border-green-500', 'border-[#11ff3b]')
text = text.replace('text-green-400', 'text-[#11ff3b]')
text = text.replace('text-green-450', 'text-[#11ff3b]')
text = text.replace('bg-green-600', 'bg-zinc-800 text-[#11ff3b] glow-green hover:bg-[#11ff3b] hover:text-black hover:glow-none transition-all')

# Fix UI chat mentions if any remained out of `renderCompletedState`
# Remove anything about chatOpen, setChatOpen from consts
text = re.sub(r'const \[chatOpen, setChatOpen\] = useState\(false\);\n?', '', text)
text = re.sub(r'const \[chatInput, setChatInput\] = useState\(\x27\x27\);\n?', '', text)
text = re.sub(r'const \[chatHistory, setChatHistory\] = useState<ChatMessage\[\]>\(\[\]\);\n?', '', text)
text = re.sub(r'const \[chatLoading, setChatLoading\] = useState\(false\);\n?', '', text)
text = re.sub(r'const chatEndRef = useRef<HTMLDivElement>\(null\);\n?', '', text)

with open('frontend/src/app/page.tsx', 'w') as f:
    f.write(text)

