#!/usr/bin/env python3
"""Find cycles in the graph stored in asms/cpa.db

This script loads the `graph` table and prints directed cycles found.

Usage examples:
  python asms/_cycle.py asms/cpa.db
  python asms/_cycle.py asms/cpa.db --max-cycles 50 --show-choices
"""

import sqlite3
import argparse
from typing import Dict, Tuple, List, Optional, Set

Node = Tuple[int, str]

def load_graph(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("SELECT tScriptid, tThread, hScriptid, hThread, choice FROM graph")
    adj: Dict[Node, List[Tuple[Node, Optional[str]]]] = {}
    nodes: Set[Node] = set()
    for tScriptid, tThread, hScriptid, hThread, choice in cur:
        tail = (tScriptid, tThread)
        head = (hScriptid, hThread)
        nodes.add(tail)
        nodes.add(head)
        adj.setdefault(tail, []).append((head, choice))
    return adj, nodes


def tarjan_scc(adj: Dict[Node, List[Tuple[Node, Optional[str]]]]):
    index = {}
    lowlink = {}
    stack = []
    onstack = set()
    result = []
    idx = 0

    def strongconnect(v):
        nonlocal idx
        index[v] = idx
        lowlink[v] = idx
        idx += 1
        stack.append(v)
        onstack.add(v)

        for (w, _) in adj.get(v, []):
            if w not in index:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in onstack:
                lowlink[v] = min(lowlink[v], index[w])

        if lowlink[v] == index[v]:
            scc = []
            while True:
                w = stack.pop()
                onstack.remove(w)
                scc.append(w)
                if w == v:
                    break
            result.append(scc)

    # Run on all nodes that appear as tails or heads
    all_nodes = set(adj.keys())
    for tails in adj.values():
        for (h, _) in tails:
            all_nodes.add(h)

    for v in sorted(all_nodes):
        if v not in index:
            strongconnect(v)

    return result


def find_cycles_in_scc(scc: List[Node], adj: Dict[Node, List[Tuple[Node, Optional[str]]]],
                       max_cycles: int, show_choices: bool):
    """Enumerate simple cycles inside an SCC.

    Strategy: for each start node s (in sorted order) do a DFS that only visits nodes >= s
    (lexicographic) to avoid duplicates. This is a simplified variant of Johnson's algorithm.
    """
    scc_set = set(scc)
    cycles = []

    sorted_nodes = sorted(scc)

    def dfs(start: Node, current: Node, path: List[Node], choices: List[Optional[str]], visited: Set[Node]):
        nonlocal cycles
        if len(cycles) >= max_cycles:
            return
        for (nbr, choice) in adj.get(current, []):
            if nbr not in scc_set:
                continue
            # enforce canonical ordering to avoid duplicates
            if nbr < start:
                continue
            if nbr == start:
                # found a cycle
                cycle_nodes = path[:]  # includes start..current
                cycle_choices = choices[:]
                cycles.append((cycle_nodes, cycle_choices))
                if len(cycles) >= max_cycles:
                    return
            elif nbr not in visited:
                visited.add(nbr)
                path.append(nbr)
                choices.append(choice)
                dfs(start, nbr, path, choices, visited)
                choices.pop()
                path.pop()
                visited.remove(nbr)

    for start in sorted_nodes:
        # quick self-loop check
        for (nbr, choice) in adj.get(start, []):
            if nbr == start:
                cycles.append(([start], [choice]))
                if len(cycles) >= max_cycles:
                    return cycles

        visited = {start}
        dfs(start, start, [start], [], visited)
        if len(cycles) >= max_cycles:
            break

    return cycles


def main():
    parser = argparse.ArgumentParser(description="Find cycles in graph stored in SQLite database")
    parser.add_argument("db", help="Path to sqlite database file (e.g. asms/cpa.db)")
    parser.add_argument("--max-cycles", type=int, default=200, help="Maximum cycles to print (default 200)")
    parser.add_argument("--max-scc-size", type=int, default=500, help="Skip SCCs larger than this size (default 500)")
    parser.add_argument("--show-choices", action='store_true', help="Also show choice labels per edge")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    print(f"Loading graph from {args.db}...")
    adj, nodes = load_graph(conn)
    total_edges = sum(len(v) for v in adj.values())
    print(f"Graph loaded: {len(nodes)} nodes, {total_edges} edges (tail nodes: {len(adj)})")

    print("Computing strongly-connected components (Tarjan)...")
    sccs = tarjan_scc(adj)
    print(f"Found {len(sccs)} SCCs")

    total_cycles = 0
    printed = 0
    for scc in sorted(sccs, key=lambda s: (-len(s), sorted(s)[0])):
        if len(scc) == 1:
            # only self-loop counts
            node = scc[0]
            has_self = any(h == node for (h, _) in adj.get(node, []))
            if not has_self:
                continue
        if len(scc) > args.max_scc_size:
            print(f"Skipping large SCC of size {len(scc)}")
            continue

        cycles = find_cycles_in_scc(scc, adj, args.max_cycles - printed, args.show_choices)
        if not cycles:
            continue

        print(f"SCC size {len(scc)}: example node {scc[0]} -> {len(cycles)} cycles found (printing up to remaining limit)")
        for (nodes_path, choices) in cycles:
            total_cycles += 1
            printed += 1
            if args.show_choices:
                # print nodes with choices between them
                parts = []
                for i, n in enumerate(nodes_path):
                    if i == 0:
                        parts.append(str(n))
                    else:
                        parts.append(f"--{repr(choices[i-1])}--> {n}")
                print(f"  cycle {total_cycles}: " + " ".join(parts))
            else:
                print(f"  cycle {total_cycles}: " + " -> ".join(str(n) for n in nodes_path))

            if printed >= args.max_cycles:
                break

        if printed >= args.max_cycles:
            break

    if total_cycles == 0:
        print("No cycles found.")
    else:
        print(f"Total cycles printed: {printed}")

    conn.close()


if __name__ == '__main__':
    main()
