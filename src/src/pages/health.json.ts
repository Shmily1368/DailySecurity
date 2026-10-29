import { getManifest } from '../lib/site';
export function GET() { return Response.json(getManifest()); }
