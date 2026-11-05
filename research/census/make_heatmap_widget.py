#!/usr/bin/env python3
"""把 out/census_summary.json 里的包含度矩阵转成报告里那张热力图的数据行和绘图代码。

输出一行 JSX（报告文档的图表组件要求单行）。数字全部来自 census_summary.json。
用法：python3 make_heatmap_widget.py > /tmp/heatmap_widget.txt
"""
import json
import pathlib

SHORT = {
    "TheSpeedX/PROXY-List": "TheSpeedX", "monosans/proxy-list": "monosans",
    "proxifly/free-proxy-list": "proxifly", "roosterkid/openproxylist": "roosterkid",
    "mmpx12/proxy-list": "mmpx12", "hookzof/socks5_list": "hookzof",
    "vakhov/fresh-proxy-list": "vakhov", "zloi-user/hideip.me": "zloi-user",
    "Zaeem20/FREE_PROXIES_LIST": "Zaeem20", "officialputuid/KangProxy": "KangProxy",
    "iplocate/free-proxy-list": "iplocate", "sunny9577/proxy-scraper": "sunny9577",
    "Vann-Dev/proxy-list": "Vann-Dev", "xyzs996/free-proxy-health-list": "xyzs996",
    "dpangestuw/Free-Proxy": "dpangestuw", "ErcinDedeoglu/proxies": "ErcinDedeoglu",
    "SevenworksDev/proxy-list": "SevenworksDev", "gfpcom/free-proxy-list (wiki)": "gfpcom",
}


def js(v):
    return "'" + str(v).replace("'", "") + "'"


def main():
    d = json.loads((pathlib.Path(__file__).parent / "out" / "census_summary.json").read_text(encoding="utf-8"))
    by_name = {s["name"]: s for s in d["sources"]}
    core = sorted(d["core_sources"], key=lambda n: -by_name[n]["latest_size"])
    agg = sorted(d["aggregators"], key=lambda n: by_name[n]["latest_size"])
    order = core + agg
    # 标题说的是“包含其他来源最多”的那一列：取各行包含度最小值最大的来源，高亮它
    ov = d["overlap_pct_row_in_col"]
    floor_of = {b: min(ov[a][b] for a in order if a != b and ov[a][b] is not None) for b in order}
    top_col = max(order, key=lambda b: floor_of[b])
    src_rows = ",".join(
        f"{{n:{js(SHORT[n])},agg:{1 if n in agg else 0},hi:{1 if n == top_col else 0}}}" for n in order)
    cells = []
    for a in order:
        for b in order:
            if a == b:
                continue
            p = ov[a][b]
            if p is None or p < 0.5:
                continue
            cells.append(f"{{r:{js(SHORT[a])},c:{js(SHORT[b])},p:{p}}}")
    cell_rows = ",".join(cells)
    n = len(order)
    left, y0, cw, ch = 110, 150, 30, 24
    height = y0 + ch * n + 18
    floor_pct = int(floor_of[top_col])
    title = f"其余 {n - 1} 个来源，每个都有 {floor_pct}% 以上的条目出现在 {SHORT[top_col]} 里"
    code = (
        "export default () => <claude.Visualize data-claude-component='source-containment' "
        f"sources={{{{src:{{kind:'data', data:[{src_rows}]}}, cells:{{kind:'data', data:[{cell_rows}]}}}}}}>"
        "{({src, cells, datum}) => { "
        f"const left = {left}, y0 = {y0}, cw = {cw}, ch = {ch}; "
        "const pos = new Map(src.map((s, i) => [s.n, i])); "
        "const nCore = src.filter(s => !s.agg).length; "
        "const hi = new Set(src.filter(s => s.hi).map(s => s.n)); "
        "const xs = n => left + pos.get(n) * cw, ys = n => y0 + pos.get(n) * ch; "
        f"return <svg viewBox='0 0 760 {height}' role='img' aria-label='{title}' fontSize='11'>"
        f"<text data-claude-text-id='title' x='0' y='18' fontSize='16' fill='var(--cds-text-primary)'>{title}</text>"
        "<text data-claude-text-id='subtitle' x='0' y='38' fill='var(--cds-text-secondary)'>"
        "行和列都按最新条目数从多到少排，聚合器在右。格子越深，行来源的条目越多地出现在列来源里；80% 以上标出数字。</text>"
        "<g data-claude-anchor='grid'>{src.map(s => <line key={s.n} x1={left} x2={left + cw * src.length} "
        "y1={ys(s.n) + ch} y2={ys(s.n) + ch} stroke='var(--cds-chart-grid)' />)}</g>"
        "<g data-claude-anchor='row-labels'>{src.map(s => <g key={s.n}>"
        "<text x={left - 8} y={ys(s.n) + 16} textAnchor='end' fill='var(--cds-text-primary)' {...datum(s, 'n')}>{s.n}</text>"
        "</g>)}</g>"
        "<g data-claude-anchor='col-labels'>{src.map(s => <text key={s.n} "
        "transform={`translate(${xs(s.n) + cw / 2 + 4}, ${y0 - 8}) rotate(-50)`} "
        "fill='var(--cds-text-primary)' {...datum(s, 'n')}>{s.n}</text>)}</g>"
        "<g data-claude-anchor='diagonal'>{src.map(s => <line key={s.n} x1={xs(s.n) + 6} y1={ys(s.n) + 5} "
        "x2={xs(s.n) + cw - 6} y2={ys(s.n) + ch - 5} stroke='var(--cds-chart-axis)' />)}</g>"
        "<g data-claude-anchor='cells'>{cells.map(r => <g key={r.r + r.c}>"
        "<rect x={xs(r.c) + 1} y={ys(r.r) + 1} width={cw - 2} height={ch - 2} "
        "fill={hi.has(r.c) ? 'var(--cds-chart-categorical-1)' : 'var(--cds-chart-muted)'} "
        "fillOpacity={hi.has(r.c) ? 0.05 + 0.6 * r.p / 100 : 0.06 + 0.94 * r.p / 100} {...datum(r, 'p')}>"
        "<title>{`${r.r} 的条目有 ${r.p}% 也在 ${r.c} 里`}</title></rect>"
        "{r.p >= 80 ? <text x={xs(r.c) + cw / 2} y={ys(r.r) + 16} textAnchor='middle' "
        "fill='var(--cds-text-primary)' {...datum(r, 'p')}>{Math.round(r.p)}</text> : null}</g>)}</g>"
        "<g data-claude-anchor='aggregator-mark'>"
        "<line x1={left + nCore * cw} x2={left + nCore * cw} y1={y0 - 4} y2={y0 + ch * src.length} "
        "stroke='var(--cds-chart-axis)' />"
        "<line x1={left + nCore * cw + 4} x2={left + cw * src.length - 2} y1='62' y2='62' stroke='var(--cds-chart-axis)' />"
        "<text data-claude-text-id='agg-label' x={left + nCore * cw + 4} y='56' fill='var(--cds-text-secondary)'>聚合器</text>"
        "</g></svg>; }}</claude.Visualize>;"
    )
    print(code)


if __name__ == "__main__":
    main()
