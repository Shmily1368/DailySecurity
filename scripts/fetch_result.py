class FetchBatch(list):
    """List-compatible fetch results with machine-readable window/health state."""

    def __init__(self, items=(), **meta):
        super().__init__(items)
        self.meta = meta
