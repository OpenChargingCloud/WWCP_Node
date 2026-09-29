import type { LogLevel } from './api/client';

export function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

/**
 * Anything on a page that can be typed into or pressed.
 *
 * Kept as one type because the only thing wanted of them here is that they can
 * all be switched off and on again.
 */
type Control = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement | HTMLButtonElement;

/** What a page says while it is telling the node. */
export const beingSaved = 'Saving ...';

/**
 * Hold a part of a page still while the node is being told, and say so.
 *
 * Measured on the vehicle's web interface, over a link that took two seconds
 * to answer: somebody pressed Save and carried on working, as anybody does when
 * nothing has happened yet. The answer arrived, the page redrew itself from
 * it, and what had been typed in the meantime was simply gone - and the page
 * said "Saved, and in effect.". Holding it still makes that impossible rather
 * than unlikely: what cannot be typed in those two seconds cannot be thrown
 * away by the answer.
 *
 * Controls that were already switched off stay off afterwards: a role that may
 * look but not change must not be handed a live form by a save that failed.
 *
 * Read every field BEFORE calling this, never inside Doing. The form is
 * switched off before Doing runs, and FormData leaves a disabled control out
 * of the form entirely - so field() in there returns the empty string and
 * isChecked() false, which a page reads as "do not change it". Measured on the
 * charging station's V2G page: it answered 200, said "Saved.", redrew itself
 * with the old values and left the file untouched. Nothing about that looks
 * like a bug from the outside.
 */
export async function whileSaving<T>(Page:    HTMLElement,
                                     Saying:  HTMLElement | null,
                                     Doing:   () => Promise<T>): Promise<T> {

    const controls      = [...Page.querySelectorAll<Control>('input, select, textarea, button')];
    const alreadyOff    = new Set(controls.filter(control => control.disabled));

    for (const control of controls)
        control.disabled = true;

    if (Saying !== null)
        Saying.textContent = beingSaved;

    try
    {
        return await Doing();
    }
    finally
    {
        for (const control of controls)
            if (!alreadyOff.has(control))
                control.disabled = false;

        // Whatever happened, it is no longer happening. What it turned into -
        // "Saved", or a sentence about why not - is the page's to say.
        if (Saying !== null)
            Saying.textContent = '';
    }

}

/**
 * Only a path of this node may be where somebody is sent after signing in.
 *
 * Asked the way a browser will read it: the path is resolved against an
 * origin of its own, and whatever arrives at any other is refused. The rule
 * was that it starts with "/" and not with "//", and a browser reads
 * "/\evil.example" and "/<tab>/evil.example" as "//evil.example" - a
 * backslash is a slash to it, and a tab or a line break is dropped before
 * anything is read. The router's pushState would have refused another
 * origin; this does not leave that to it.
 */
export function safeNext(value: string | null): string | null {

    if (value === null || !value.startsWith('/'))
        return null;

    const here = 'http://this.node.invalid';

    try {
        return new URL(value, here).origin === here ? value : null;
    }
    catch {
        return null;
    }

}

/** Read a form field as a trimmed string. */
export function field(form: HTMLFormElement, name: string, trim = true): string {
    const value = String(new FormData(form).get(name) ?? '');
    return trim ? value.trim() : value;
}

/** Whether one box of a form is ticked. */
export function isChecked(form: HTMLFormElement, name: string): boolean {
    return new FormData(form).get(name) !== null;
}

/**
 * Read a form field as a number; NaN when it is empty or not one.
 *
 * Empty is asked first, because Number('') is 0: on the energy meter, a field
 * somebody emptied went to the meter as 0 - no retries, no CNAME followed, a
 * timeout the meter refused the whole save over - where it said nothing. NaN
 * goes as null, which the node takes for not given.
 */
export function numberField(form: HTMLFormElement, name: string): number {
    return numberFrom(field(form, name));
}

/**
 * Read what was typed as a number, as numberField reads a form's field: NaN
 * when it is empty or not one. For an input outside a form - a port in a row
 * of the name servers, which Number(input.value) made 0 once emptied, where the
 * node takes no port for the port of the transport.
 */
export function numberFrom(Text: string): number {
    const text = Text.trim();
    return text === '' ? NaN : Number(text);
}


/**
 * Put text on the clipboard, and say what happened in words a person can act
 * on.
 *
 * The clipboard is only there on a secure origin, and a node reached at a LAN
 * address over plain HTTP is not one. Saying so beats a button that silently
 * does nothing - which is why this returns a message rather than a boolean.
 */
export async function copyText(Text: string, Fallback?: HTMLInputElement | HTMLTextAreaElement): Promise<string> {

    try {
        await navigator.clipboard.writeText(Text);
        return 'Copied.';
    }
    catch {

        Fallback?.select();

        return Fallback
                   ? 'Selected - copy it with Ctrl+C.'
                   : 'This browser will not let the page copy; select the text and copy it.';

    }

}


// Times

/**
 * The formatters, made once.
 *
 * toLocaleTimeString builds one of these on every call, and the log page calls
 * it once per line: 234 ms of a 597 ms redraw at 1959 entries went on the
 * clock alone, against 63 ms with the formatter kept. It reads the browser's
 * locale when the page loads, which is the one moment it can change.
 */
const timeOfDay = new Intl.DateTimeFormat([], {
                          hour:                    '2-digit',
                          minute:                  '2-digit',
                          second:                  '2-digit',
                          fractionalSecondDigits:  3,
                          hour12:                  false
                      });

const wholeMoment = new Intl.DateTimeFormat([], { dateStyle: 'medium', timeStyle: 'medium' });

/** The time of day with milliseconds - the column in front of every log line. */
export function formatTime(iso: string): string {

    const date = new Date(iso);

    if (Number.isNaN(date.getTime()))
        return iso;

    return timeOfDay.format(date);

}

/**
 * What a format's locale writes between the seconds and their fraction - "."
 * in English, "," in German - as the time of day in front of every log line
 * writes it. Asked once for each format: the log page asks for a moment once
 * for each line.
 */
const fractionSeparators = new WeakMap<Intl.DateTimeFormat, string>();

function fractionSeparatorOf(Moment: Intl.DateTimeFormat): string {

    let separator = fractionSeparators.get(Moment);

    if (separator === undefined)
    {

        const parts  = new Intl.DateTimeFormat(Moment.resolvedOptions().locale, { second: '2-digit', fractionalSecondDigits: 3 }).
                           formatToParts(0);
        const at     = parts.findIndex(part => part.type === 'fractionalSecond');

        separator    = at > 0 && parts[at - 1]!.type === 'literal' ? parts[at - 1]!.value : '.';

        fractionSeparators.set(Moment, separator);

    }

    return separator;

}

/**
 * The whole moment, for the title of a log line and for the details - its
 * milliseconds after the seconds, where the locale writes the seconds: added
 * to the end, they came after the "PM" of a twelve-hour clock, "3:52:17
 * PM.123". A date style and fractional seconds cannot be asked of one format.
 * And set off from them as the locale sets them off, as the time of day in
 * front of the same line does: "16:47:22,700" beside "16:47:22.700" was one
 * moment written two ways (found by the meter).
 */
export function formatTimestamp(iso:     string,
                                Moment:  Intl.DateTimeFormat = wholeMoment): string {

    const date = new Date(iso);

    if (Number.isNaN(date.getTime()))
        return iso;

    const milliseconds = fractionSeparatorOf(Moment) + String(date.getMilliseconds()).padStart(3, '0');

    return Moment.formatToParts(date).
                  map(part => part.type === 'second' ? part.value + milliseconds : part.value).
                  join('');

}

/** How long ago, in the words somebody would use. */
export function formatSince(iso: string): string {

    const then = new Date(iso).getTime();

    if (Number.isNaN(then))
        return iso;

    const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));

    if (seconds <   60)  return `${seconds}s ago`;
    if (seconds < 3600)  return `${Math.round(seconds /    60)}m ago`;
    if (seconds < 86400) return `${Math.round(seconds /  3600)}h ago`;

    return `${Math.round(seconds / 86400)}d ago`;

}


// Numbers

/**
 * A measurement, with the digits it is worth and nothing where there is no
 * value. An empty cell reads as a page that failed to render.
 */
export function formatNumber(value: number | null | undefined, digits = 2): string {

    if (value === null || value === undefined || Number.isNaN(value))
        return '-';

    return value.toLocaleString([], {
               minimumFractionDigits: digits,
               maximumFractionDigits: digits
           });

}


// Values of the configuration page

/**
 * One value of the configuration, as a line of text. Everything the node
 * sends is rendered, whether this page knew about it or not - so a new field
 * on the server shows up here without a change.
 */
export function formatValue(value: unknown): string {

    if (value === null || value === undefined)
        return '-';

    if (typeof value === 'boolean')
        return value ? 'yes' : 'no';

    if (Array.isArray(value))
        return value.length === 0 ? '-' : value.map(formatValue).join(', ');

    if (typeof value === 'object')
        return JSON.stringify(value);

    // A field the node left empty is a field with nothing in it, and an empty
    // cell reads as a page that failed to render.
    const text = String(value);

    if (text.trim().length === 0)
        return '-';

    // The node writes its times in ISO 8601, which is the right thing to send
    // and the wrong thing to read.
    if (isTimestamp(text))
        return formatTimestamp(text);

    return text;

}

/** Whether a string is an ISO 8601 moment, as the node writes them. */
function isTimestamp(text: string): boolean {
    return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(text) &&
           !Number.isNaN(new Date(text).getTime());
}

/**
 * The words that are not words: an acronym the node sends in lower case
 * belongs on the page in the case people write it in. Every kind of node's
 * list, in one: no word of it is spelt two ways.
 */
const acronyms = new Map<string, string>([
    ['id',    'ID'],
    ['url',   'URL'],
    ['uri',   'URI'],
    ['http',  'HTTP'],
    ['https', 'HTTPS'],
    ['api',   'API'],
    ['os',    'OS'],
    ['nts',   'NTS'],
    ['ntp',   'NTP'],
    ['dns',   'DNS'],
    ['tls',   'TLS'],
    ['udp',   'UDP'],
    ['edns',  'EDNS'],
    ['ttl',   'TTL'],
    ['aead',  'AEAD'],
    ['ke',    'KE'],
    ['aeadalgorithms', 'AEAD algorithms'],
    ['mac',   'MAC'],
    ['ms',    'ms'],
    ['kw',    'kW'],
    ['kwh',   'kWh'],
    ['ocpp',  'OCPP'],
    ['csms',  'CSMS'],
    ['evse',  'EVSE'],
    ['evses', 'EVSEs'],
    ['v2g',   'V2G'],
    ['mo',    'MO'],
    ['sdp',   'SDP'],
    ['slac',  'SLAC'],
    ['secc',  'SECC'],
    ['evcc',  'EVCC'],
    ['vin',   'VIN'],
    ['soc',   'SoC'],
    ['ocpi',  'OCPI'],
    ['cpo',   'CPO'],
    ['emsp',  'EMSP'],
    ['cdr',   'CDR'],
    ['cdrs',  'CDRs'],
    ['uid',   'UID']
]);

/** "frontendFiles" reads better as "Frontend files". */
export function humanizeKey(key: string): string {

    const words = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').
                      replace(/_/g, ' ').
                      split(' ').
                      filter(word => word.length > 0);

    return words.map((word, index) => {

               const acronym = acronyms.get(word.toLowerCase());

               if (acronym !== undefined)
                   return acronym;

               // Only the first word is capitalised: "Server name", not
               // "Server Name" - this is a label, not a headline.
               return index === 0
                          ? word.charAt(0).toUpperCase() + word.slice(1)
                          : word.toLowerCase();

           }).join(' ');

}


// Log levels

/** Whether a level is at least as loud as another. */
export function isAtLeast(level: LogLevel, minimum: LogLevel): boolean {

    const order: LogLevel[] = ['debug', 'info', 'notice', 'warning', 'error', 'critical'];

    return order.indexOf(level) >= order.indexOf(minimum);

}
