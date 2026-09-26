import {
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'


function Pagination({
  total,
  limit,
  offset,
  onChange,
}) {
  const currentPage = Math.floor(offset / limit) + 1
  const totalPages = Math.max(
    1,
    Math.ceil(total / limit),
  )

  const start = total === 0
    ? 0
    : offset + 1

  const end = Math.min(
    offset + limit,
    total,
  )

  return (
    <div className="pagination">
      <span>
        {start}–{end} of {total.toLocaleString()}
      </span>

      <div>
        <button
          disabled={offset === 0}
          onClick={() => {
            onChange(
              Math.max(0, offset - limit),
            )
          }}
        >
          <ChevronLeft size={15} />
        </button>

        <span className="page-number">
          {currentPage} / {totalPages}
        </span>

        <button
          disabled={offset + limit >= total}
          onClick={() => {
            onChange(offset + limit)
          }}
        >
          <ChevronRight size={15} />
        </button>
      </div>
    </div>
  )
}


export default Pagination