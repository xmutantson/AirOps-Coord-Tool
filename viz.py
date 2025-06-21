#!/usr/bin/env python3
import os, json, re
import sqlite3
from bs4 import BeautifulSoup
from tinycss2 import parse_stylesheet

# ——— Helpers ———————————————————————————————————————————————————————

def scan_html(dom_dir):
    nodes, links, page_map = [], [], {}
    for root, _, files in os.walk(dom_dir):
        for fn in files:
            if not fn.endswith('.html'): continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, dom_dir)
            page_id = f"page:{rel}"
            nodes.append({'id': page_id, 'group':'PAGE', 'label': rel})
            page_map[rel] = page_id

            html = open(path, 'r', encoding='utf-8').read()
            soup = BeautifulSoup(html, 'html.parser')

            # link page-><html>
            root_el = soup.find('html')
            if root_el:
                uid = f"html:{rel}:html:{id(root_el)}"
                nodes.append({'id': uid, 'group':'DOM', 'label':'html'})
                links.append({'source': page_id, 'target': uid})

            # DOM nodes + hierarchy + page links
            for el in soup.find_all(True):
                uid = f"html:{rel}:{el.name}:{id(el)}"
                nodes.append({'id': uid, 'group':'DOM', 'label': el.name})
                # hierarchy
                if el.parent and el.parent.name:
                    pid = f"html:{rel}:{el.parent.name}:{id(el.parent)}"
                    links.append({'source': pid, 'target': uid})
                # page->dom
                links.append({'source': page_id, 'target': uid})
                # CSS class/id linking
                classes = el.get('class') or []
                for cls in classes:
                    sel_id = f"css:style.css:.{cls}"
                    links.append({'source': f"html:{rel}:{el.name}:{id(el)}", 'target': sel_id})
                if el.get('id'):
                    sel_id = f"css:style.css:#{el.get('id')}"
                    links.append({'source': f"html:{rel}:{el.name}:{id(el)}", 'target': sel_id})

            # Inline JS
            for idx, tag in enumerate(soup.find_all('script')):
                js_text = tag.string or ''
                js_id = f"inline_js:{rel}:script{idx}"
                nodes.append({'id': js_id, 'group':'JS', 'label': f"{rel}@script#{idx}"})
                tag_uid = f"html:{rel}:script:{id(tag)}"
                nodes.append({'id': tag_uid, 'group':'DOM', 'label':'script'})
                links.append({'source': page_id, 'target': tag_uid})
                links.append({'source': tag_uid, 'target': js_id})
                for fn_name in re.findall(r'function\s+([A-Za-z_]\w*)', js_text):
                    fn_id = f"{js_id}:fn:{fn_name}"
                    nodes.append({'id': fn_id, 'group':'JS', 'label': fn_name})
                    links.append({'source': js_id, 'target': fn_id})
                for sel in re.findall(r"""document\.querySelector\(['\"](.+?)['\"]\)""", js_text):
                    sel_id = f"css:style.css:{sel}"
                    nodes.append({'id': sel_id, 'group':'CSS', 'label': sel})
                    links.append({'source': js_id, 'target': sel_id})

    return nodes, links, page_map


def scan_css(css_path):
    nodes, links, css_ids = [], [], []
    rules = parse_stylesheet(open(css_path, 'r', encoding='utf-8').read(), skip_comments=True)
    for r in rules:
        if r.type != 'qualified-rule': continue
        sel = ''.join([t.serialize() for t in r.prelude]).strip()
        sid = f"css:{os.path.basename(css_path)}:{sel}"
        nodes.append({'id': sid, 'group':'CSS', 'label': sel})
        css_ids.append(sid)
        # naive tag match
        tag_match = re.match(r'^([a-zA-Z][\w-]*)', sel)
        if tag_match:
            tag = tag_match.group(1)
            for n in nodes:
                if n['group']=='DOM' and n['label']==tag:
                    links.append({'source': sid, 'target': n['id']})
    return nodes, links, css_ids


def scan_db(db_file):
    nodes, links, tables = [], [], []
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    for (tbl,) in cur.fetchall():
        tid = f"db:table:{tbl}"
        nodes.append({'id': tid, 'group':'DB', 'label': tbl})
        tables.append(tbl)
        try:
            cur.execute(f"PRAGMA table_info({tbl})")
            for _, col, *_ in cur.fetchall():
                cid = f"db:col:{tbl}.{col}"
                nodes.append({'id': cid, 'group':'DB', 'label': col})
                links.append({'source': tid, 'target': cid})
        except sqlite3.DatabaseError:
            # skip system tables without schema
            pass
    conn.close()
    return nodes, links, tables


def scan_app(app_path, tables):
    nodes, links = [], []
    lines = open(app_path, 'r', encoding='utf-8').read().splitlines()
    # add module-level node
    module_id = 'route:<module>'
    nodes.append({'id': module_id, 'group':'MODULE', 'label':'<module>'})

    # find route handlers
    route_positions = [( -1, '<module>' )]
    route_pattern = re.compile(r"@app\.(?:route|get|post)\(\s*['\"]([^'\"]+)['\"]")
    for idx, line in enumerate(lines):
        m = route_pattern.search(line)
        if m:
            path = m.group(1)
            route_positions.append((idx, path))
            nodes.append({'id': f"route:{path}", 'group':'ROUTE', 'label': path})
    route_positions.append((len(lines), None))

    # link routes (and module) to tables
    for i in range(len(route_positions)-1):
        start, path = route_positions[i]
        end = route_positions[i+1][0]
        segment = '\n'.join(lines[start+1:end])
        route_id = f"route:{path}"
        for tbl in tables:
            if re.search(rf"\b{tbl}\b", segment, re.IGNORECASE):
                links.append({'source': route_id, 'target': f"db:table:{tbl}"})
    # ensure all tables at least link to module
    for tbl in tables:
        links.append({'source': module_id, 'target': f"db:table:{tbl}"})

    return nodes, links


# ——— main —————————————————————————————————————————————————————————————
all_nodes, all_links = [], []

# HTML + inline JS
n, l, page_map = scan_html('templates')
all_nodes += n; all_links += l

# CSS
n, l, css_nodes = scan_css('static/style.css')
all_nodes += n; all_links += l

# DB schema
n, l, tables = scan_db('data/aircraft_ops.db')
all_nodes += n; all_links += l

# link templates to DB tables by content scan
for rel, pid in page_map.items():
    content = open(os.path.join('templates', rel), 'r', encoding='utf-8').read()
    for tbl in tables:
        if re.search(rf"\b{tbl}\b", content, re.IGNORECASE):
            all_links.append({'source': pid, 'target': f"db:table:{tbl}"})
    # link CSS rules to pages referencing style.css
    if 'style.css' in content:
        for sid in css_nodes:
            all_links.append({'source': pid, 'target': sid})

# scan app.py for route->table links + module links
n, l = scan_app('app.py', tables)
all_nodes += n; all_links += l

# link all pages to navbar in base.html
if 'base.html' in page_map:
    soup = BeautifulSoup(open('templates/base.html','r',encoding='utf-8'),'html.parser')
    nav = soup.find('nav')
    if nav:
        nav_id = f"html:base.html:nav:{id(nav)}"
        all_nodes.append({'id': nav_id, 'group':'DOM', 'label':'nav'})
        for pid in page_map.values():
            all_links.append({'source': pid, 'target': nav_id})

# dedupe nodes by ID
unique = {n['id']: n for n in all_nodes}.values()
graph = {'nodes': list(unique), 'links': all_links}
with open('graph.json', 'w', encoding='utf-8') as f:
    json.dump(graph, f, indent=2)
print("→ graph.json written")
