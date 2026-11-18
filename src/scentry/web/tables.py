"""Sorting and searching a table on the server: the portal runs no JavaScript.

A column heading is a link that sorts by it (again: the other way round), and a search
box filters the rows; both are query parameters, so a sorted, filtered table can be
bookmarked. Several tables on one page each get their own prefix ("scans_sort", ...),
and every link keeps the page's other parameters.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from starlette.datastructures import QueryParams


def _key(value: Any) -> tuple:
    """Text without regard to case; None compares as the smallest value."""
    if isinstance(value, str):
        value = value.lower()
    return (value is not None, value if value is not None else 0)


@dataclass
class View:
    """One table's rows after search and sort, and the links that change them."""

    rows: list
    total: int  # before the search
    sort: str
    desc: bool
    q: str
    prefix: str
    anchor: str
    params: list[tuple[str, str]] = field(default_factory=list)  # the page's others
    desc_first: frozenset[str] = frozenset()  # columns sorted high to low first

    def _url(self, **mine: str) -> str:
        own = [(f"{self.prefix}{k}", v) for k, v in mine.items() if v]
        query = urlencode([*self.params, *own])
        return f"?{query}#{self.anchor}"

    def href(self, column: str) -> str:
        """Sort by this column; by it the other way round if it is already sorted."""
        desc = not self.desc if column == self.sort else column in self.desc_first
        return self._url(sort=column, dir="desc" if desc else "asc", q=self.q)

    def aria(self, column: str) -> str:
        if column != self.sort:
            return "none"
        return "descending" if self.desc else "ascending"

    @property
    def hidden(self) -> list[tuple[str, str]]:
        """The inputs a search form carries so the page's other state survives."""
        own = [(f"{self.prefix}sort", self.sort),
               (f"{self.prefix}dir", "desc" if self.desc else "asc")]  # fmt: skip
        return [*self.params, *own]

    @property
    def search_name(self) -> str:
        return f"{self.prefix}q"

    @property
    def clear(self) -> str:
        """The same table without the search."""
        return self._url(sort=self.sort, dir="desc" if self.desc else "asc")


# Parameters that are about this one showing of the page, not kept by sorting or searching:
# a paused refresh, and the add-target form shown again after a mistake.
ONCE = frozenset({"refresh", "error", "source", "add"})


def view(
    params: QueryParams,
    rows: Iterable,
    *,
    sorts: dict[str, Callable[[Any], Any]],
    default: str,
    text: Callable[[Any], Iterable[str | None]],
    prefix: str = "",
    anchor: str = "",
    desc_first: Iterable[str] = (),
    default_desc: bool = False,
) -> View:
    """Search `rows` (every word must appear in one of `text(row)`) and sort them by the
    column the query asks for, else `default`. `desc_first`: columns whose first click
    sorts high to low (scores, dates, counts). Empty values sort last either way."""
    rows = list(rows)
    total = len(rows)
    sort = params.get(f"{prefix}sort", "")
    if sort in sorts:
        desc = params.get(f"{prefix}dir") == "desc"
    else:
        sort, desc = default, default_desc
    q = " ".join(params.get(f"{prefix}q", "").split())[:100]
    words = q.lower().split()
    if words:
        rows = [
            r for r in rows
            if all(any(w in (t or "").lower() for t in text(r)) for w in words)
        ]  # fmt: skip
    rows.sort(key=lambda r: _key(sorts[sort](r)), reverse=desc)
    rows.sort(key=lambda r: sorts[sort](r) is None)  # stable: empty ones go last
    mine = {f"{prefix}{k}" for k in ("sort", "dir", "q")}
    others = [(k, v) for k, v in params.multi_items() if k not in mine and k not in ONCE]
    return View(rows=rows, total=total, sort=sort, desc=desc, q=q, prefix=prefix,
                anchor=anchor or prefix.rstrip("_") or "table", params=others,
                desc_first=frozenset(desc_first))  # fmt: skip
