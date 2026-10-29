import { getAllDates, getDailyDigest, payloadChunk, PAGE_SIZE } from '../../../lib/data';
import { gzipSync } from 'node:zlib';
export function getStaticPaths() {
    return getAllDates().flatMap(date => {
        const count = Math.ceil(getDailyDigest(date).items.length / PAGE_SIZE);
        return Array.from({ length: count }, (_, page) => {
            const hash = payloadChunk(date, page).url.split('/').pop()!.replace('.json.gz', '');
            return { params: { date, hash }, props: { date, page } };
        });
    });
}
export function GET({ props }: { props: { date: string; page: number } }) {
    return new Response(gzipSync(payloadChunk(props.date, props.page).body), { headers: { 'Content-Type': 'application/gzip' } });
}
