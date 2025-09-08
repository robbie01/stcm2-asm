#!/usr/bin/env python3
"""
dijkstra_sqlite.py

Usage:
    python dijkstra_sqlite.py /path/to/db.sqlite
    python dijkstra_sqlite.py /path/to/db.sqlite --start 99 sure1 --end 9100 sure1
"""

import sqlite3
import heapq
import argparse
from typing import Tuple, Dict, List, Optional

Node = Tuple[int, str]

def load_graph(conn: sqlite3.Connection):
    """
    Load graph edges from 'graph' table.
    Returns adjacency dict:
      adj[(tScriptid, tThread)] = [ ( (hScriptid,hThread), choice ), ... ]
    Also returns set of all nodes (tail and head).
    """
    cur = conn.cursor()
    cur.execute("SELECT tScriptid, tThread, hScriptid, hThread, choice FROM graph")
    adj = {}
    nodes = set()
    for tScriptid, tThread, hScriptid, hThread, choice in cur:
        tail = (tScriptid, tThread)
        head = (hScriptid, hThread)
        nodes.add(tail)
        nodes.add(head)
        adj.setdefault(tail, []).append((head, choice))
    return adj, nodes

def load_dialogue_counts(conn: sqlite3.Connection, tails):
    """
    Get count of dialogue rows per (scriptid, thread).
    We'll query only those tails that exist (for efficiency).
    Returns dict: counts[(scriptid,thread)] = int
    """
    cur = conn.cursor()
    # Use a single GROUP BY query across whole table is usually fastest; but restrict to tails if desired.
    # We'll do a grouped query across the whole table and then filter (cheap).
    cur.execute("SELECT scriptid, thread, COUNT(*) FROM dialogue GROUP BY scriptid, thread")
    counts = {}
    for scriptid, thread, cnt in cur:
        counts[(scriptid, thread)] = int(cnt)
    # Ensure tails with no rows get 0 weight (explicit)
    for t in tails:
        counts.setdefault(t, 0)
    return counts

def dijkstra(adj: Dict[Node, List[Tuple[Node, Optional[str]]]],
             weight_for_tail: Dict[Node, int],
             start: Node,
             goal: Node):
    """
    Standard Dijkstra with heapq. Edge weight for edge from u->v is weight_for_tail[u].
    Returns: (total_cost, path_nodes_list, path_choices_list) or (None, None, None) if unreachable.
    path_choices_list aligns with edges: length = len(path_nodes)-1
    """
    INF = float('inf')
    dist = {}
    prev = {}
    prev_choice = {}

    # priority queue of (distance, node)
    pq = []
    heapq.heappush(pq, (0, start))
    dist[start] = 0

    while pq:
        d, u = heapq.heappop(pq)
        if d > dist.get(u, INF):
            continue
        if u == goal:
            break
        for (v, choice) in adj.get(u, []):
            w = weight_for_tail.get(u, 0)
            nd = d + w
            if nd < dist.get(v, INF):
                dist[v] = nd
                prev[v] = u
                prev_choice[v] = choice
                heapq.heappush(pq, (nd, v))

    if goal not in dist:
        return None, None, None

    # Reconstruct path
    path_nodes = []
    path_choices = []
    cur = goal
    while cur != start:
        path_nodes.append(cur)
        path_choices.append(prev_choice.get(cur))
        cur = prev[cur]
    path_nodes.append(start)
    path_nodes.reverse()
    path_choices.reverse()
    return dist[goal], path_nodes, path_choices

def main():
    parser = argparse.ArgumentParser(description="Run Dijkstra on graph stored in SQLite")
    parser.add_argument("db", help="Path to sqlite database file")
    parser.add_argument("--start", nargs=2, metavar=('SCRIPTID','THREAD'),
                        help="Start node: scriptid thread (default: 99 sure1)", default=None)
    parser.add_argument("--end", nargs=2, metavar=('SCRIPTID','THREAD'),
                        help="End node: scriptid thread (default: 9100 sure1)", default=None)
    args = parser.parse_args()

    if args.start:
        start = (int(args.start[0]), args.start[1])
    else:
        start = (99, "sure1")

    if args.end:
        goal = (int(args.end[0]), args.end[1])
    else:
        goal = (9100, "sure1")

    conn = sqlite3.connect(args.db)
    conn.row_factory = None

    print(f"Loading graph from {args.db} ...")
    adj, nodes = load_graph(conn)
    print(f"Graph loaded: {len(nodes)} nodes, {sum(len(v) for v in adj.values())} edges (tail nodes: {len(adj)})")

    print("Loading dialogue counts (weights)...")
    weight_for_tail = load_dialogue_counts(conn, tails=adj.keys())

    # Optional: print some stats
    # find tails with zero count (helpful)
    zeros = [t for t, c in weight_for_tail.items() if c == 0]
    if zeros:
        print(f"Note: {len(zeros)} tail nodes have 0 dialogue rows (these outgoing edges have weight 0).")

    print(f"Running Dijkstra from {start} -> {goal} ...")
    total_cost, path_nodes, path_choices = dijkstra(adj, weight_for_tail, start, goal)

    if total_cost is None:
        print("No path found.")
    else:
        print(f"Total cost: {total_cost}")
        print("Path (scriptid, thread):")
        for i, node in enumerate(path_nodes):
            if i == 0:
                print(f"  {i}: {node}")
            else:
                choice = path_choices[i-1]
                weight = weight_for_tail.get(path_nodes[i-1], 0)
                print(f"  {i}: {node}   via choice={repr(choice)}   step-weight={weight}")
    conn.close()

if __name__ == "__main__":
    main()