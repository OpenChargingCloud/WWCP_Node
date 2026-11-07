import type { NTSServerEntry, NTSTimeSource } from '../api/client';
import { draftOf, withAsShown, withPins } from './pins';

/**
 * The list of time servers as the NTS page edits it.
 *
 * Apart from the page, because this is the part that decides what the node
 * is told - and the node is told the whole list every time, so a mistake
 * here is a server deleted that nobody touched. The page around it only draws
 * and asks.
 */


/** The ports a server is asked on unless its entry says otherwise. */
export interface UsualPorts {
    ntsKE:  number;
    ntp:    number;
}


/**
 * A name as somebody reads it: without the root's dot. The node hands its
 * names back fully qualified, and "ptbtime1.ptb.de." is correct and looks like
 * a typing mistake.
 */
export function readable(hostname: string): string {
    return hostname.endsWith('.') ? hostname.slice(0, -1) : hostname;
}


/** What a server's entry sets about when its key exchange is made again. */
export interface Refresh {
    minRefreshSeconds?: number | null;
    maxRefreshSeconds?: number | null;
}

/** The node's defaults for it, where an entry sets nothing. */
export interface RefreshDefaults {
    defaultMinRefresh?: number;
    defaultMaxRefresh?: number;
}


/** Whether a server's entry sets when its key exchange is made again. */
export function refreshSet(entry: Refresh): boolean {
    return entry.minRefreshSeconds != null || entry.maxRefreshSeconds != null;
}


/**
 * When a server's key exchange is made again, as a sentence says it: "12 to
 * 24 hours", "90 minutes". What its entry sets, and the node's defaults for
 * what it does not - by the node's rule: never a latest before the earliest.
 */
export function refreshText(entry: Refresh, defaults: RefreshDefaults): string {

    const usualMin  = defaults.defaultMinRefresh ?? 43200;
    const usualMax  = defaults.defaultMaxRefresh ?? 86400;

    const min = entry.minRefreshSeconds ?? (entry.maxRefreshSeconds != null && entry.maxRefreshSeconds < usualMin ? entry.maxRefreshSeconds : usualMin);
    const max = entry.maxRefreshSeconds ?? Math.max(min, usualMax);

    const [ unit, name ] = min % 3600 === 0 && max % 3600 === 0 ? [ 3600, 'hours' ]
                         : min %   60 === 0 && max %   60 === 0 ? [   60, 'minutes' ]
                         :                                         [    1, 'seconds' ];

    const shown = (seconds: number): string => String(Math.round(seconds / unit * 100) / 100);

    return min === max
               ? `${shown(max)} ${name}`
               : `${shown(min)} to ${shown(max)} ${name}`;

}


/**
 * Whether two names are the same server's: compared without the root's dot,
 * and without case.
 */
function sameName(one: string, other: string): boolean {
    return readable(one.trim()).toLowerCase() === readable(other.trim()).toLowerCase();
}


/**
 * A server as the node shows it, turned back into what its configuration
 * says - with everything that is the usual left out, and what it is held to
 * kept in.
 *
 * Left out rather than repeated, because the node writes back what it is
 * sent: an entry carrying the usual ports and priority 0 becomes an object in
 * the file where a bare name was, and the file stops reading the way somebody
 * would have written it.
 *
 * What it is held to in every entry, in the keys the file writes it under,
 * because the list sent replaces the node's whole: an entry
 * without it is a server held to nothing from then on. Measured so: the save
 * of ptbtime2.ptb.de's priority took the root ptbtime1.ptb.de had learned on
 * first use, and the instruction to learn it, out of the file and out of
 * effect, and the log said no more than that it was held to no fingerprint.
 *
 * Its id as well, by the same rule: one left out is given anew by the
 * server's place in the list, and a CSMS that knew the server by the old one
 * would find another server under it after the next save.
 *
 * And the AEAD algorithm its entry offers, where it names one: left out, the
 * next save of any server would make it offer every one again. And when its
 * key exchange is made again, where its entry sets that, by the same rule.
 */
export function entryOf(source: NTSTimeSource, usual: UsualPorts): NTSServerEntry {

    const entry: NTSServerEntry = { hostname: readable(source.hostname) };

    if (source.id)                         entry.id         = source.id;
    if (source.priority  !== 0)            entry.priority   = source.priority;
    if (source.ntsKEPort !== usual.ntsKE)  entry.ntsKEPort  = source.ntsKEPort;
    if (source.ntpPort   !== usual.ntp)    entry.ntpPort    = source.ntpPort;
    if (!source.enabled)                   entry.enabled    = false;
    if (source.aead)                       entry.aead       = source.aead;
    if (source.minRefreshSeconds != null)  entry.minRefreshSeconds = source.minRefreshSeconds;
    if (source.maxRefreshSeconds != null)  entry.maxRefreshSeconds = source.maxRefreshSeconds;

    return withPins(entry, draftOf(source.heldTo));

}


/**
 * A time server as the page sends it back: its entry, and what the page
 * showed it held to - because a root it learned after the page was loaded is
 * not in what the page shows, and the node keeps it only where it
 * is told so; see asShown.
 */
export function sentOf(source: NTSTimeSource, usual: UsualPorts): NTSServerEntry {
    return withAsShown(entryOf(source, usual), source.heldTo);
}


/**
 * The list with one server replaced, or with one added at the end when there
 * is no place given.
 *
 * A new list rather than the old one changed: the old one is what the node
 * still has, and it is what the page has to go back to when the node says
 * no.
 */
export function withServer(list:   readonly NTSServerEntry[],
                           index:  number | null,
                           entry:  NTSServerEntry): NTSServerEntry[] {

    return index === null
               ? [...list, entry]
               : list.map((other, at) => at === index ? entry : other);

}


/** The list without the server at that place. */
export function withoutServer(list:   readonly NTSServerEntry[],
                              index:  number): NTSServerEntry[] {

    return list.filter((_, at) => at !== index);

}


/**
 * Whether another server of the list already has this name - the one at the
 * place being edited does not count, or a server could not be saved unchanged.
 *
 * Compared the way names compare: without the root's dot, and without case.
 */
export function nameTaken(list:      readonly NTSServerEntry[],
                          hostname:  string,
                          except:    number | null): boolean {

    return list.some((other, at) => at !== except &&
                                    sameName(other.hostname, hostname));

}
