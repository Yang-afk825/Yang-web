# Yang-Web v2.1 UI Fix - 2026-06-24

## Done
1. **url_analyzer.py complete rewrite** (49KB, 932 lines, ASCII-only):
   - POST form attack support (was only GET before)
   - All 7 core functions working
   - Clean English, no encoding issues

2. **Attack status fix**: `_show_attack_result` now updates status label to show completion
   - Before: stuck at "🔄 Attacking..." forever
   - Now: shows "✅ Attack done: XXX | HTTP 200 | 201ms"

3. **Real Back button**: 
   - Full "⬅️ Return to Vulnerability List" button at top of attack response view
   - Clicking re-renders vulnerability cards via `_render_results(_last_analyze_result)`
   - Replaces old "collapse response" button that was buried at bottom
