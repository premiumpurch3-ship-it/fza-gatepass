from fastapi import Query


class Page:
    def __init__(self, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100)):
        self.page, self.size = page, page_size

    @property
    def offset(self):
        return (self.page - 1) * self.size


def envelope(items, total, pg: Page):
    return {"items": items, "total": total, "page": pg.page, "page_size": pg.size,
            "pages": max(1, -(-total // pg.size))}
