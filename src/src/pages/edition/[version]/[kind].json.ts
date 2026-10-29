import { getCatalog, getSearchIndex, getManifest } from '../../../lib/site';
export function getStaticPaths() {
    return ['catalog', 'search'].map(kind => ({ params: { version: getManifest().version, kind } }));
}
export function GET({ params }: { params: { kind: string } }) {
    return Response.json(params.kind === 'catalog' ? getCatalog() : getSearchIndex());
}
