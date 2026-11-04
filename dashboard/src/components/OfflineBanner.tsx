export default function OfflineBanner({ detail }: { detail?: string }) {
  return (
    <div
      role="alert"
      className="rounded-md border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900"
    >
      <p className="font-semibold">
        API offline — start the API (see api/README.md)
      </p>
      <p className="mt-1">
        No data is shown below because the Management API could not be
        reached. No sample or placeholder rows are displayed in its place.
        {detail ? ` ${detail}` : ''}
      </p>
    </div>
  );
}
