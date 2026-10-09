import type { CertificateStore } from '../api/client';

/**
 * What a certificate of a kind may be told it is for, as the certificates
 * page offers it.
 *
 * Apart from the page, because this is the part that decides what the page
 * offers - and it offered one list for every kind: the services a TLS root
 * vouches for, "dns" and "nts", were offered for a TLS identity as well, which
 * was told the listeners it is shown on - a TLS server identity is now - and
 * of which most nodes have none.
 * The EV found it and every kind but the local controller took it; in a page
 * every node shares it would have offered a meter's identity the name
 * servers instead of its Modbus/TLS and web listeners.
 */


/** What a usage is called on the page, unless a kind of node calls it something else: the service, in the words of the pages it is set on. */
const usageNames: Record<string, string> = {
    dns:  'name servers (DNS)',
    nts:  'time servers (NTS)'
};

export function usageName(Usage: string, Names: Record<string, string> = {}): string {
    return Names[Usage] ?? usageNames[Usage] ?? Usage;
}


/**
 * What a certificate of this kind may be told it is for in this store - what
 * the store says of the kind, and nothing for a kind it tells nothing. The
 * list is what counts: the node says "hasUsages" where it is not empty, and
 * nowhere else (CertificateStore.HasUsages).
 */
export function usagesOf(Store: CertificateStore, Kind: string): string[] {
    return Store.kinds[Kind]?.usages ?? [];
}


/** Whether a certificate of this kind is told what it is for in this store at all. */
export function hasUsages(Store: CertificateStore, Kind: string): boolean {
    return usagesOf(Store, Kind).length > 0;
}
