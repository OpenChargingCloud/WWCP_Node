import { logLevels, type LogEntry, type LogLevel } from '../api/client';
import { config } from '../config';
import { html as stringHTML, must } from '../html';
import { drawOrder, entryAt } from '../logs/order';
import { logs } from '../logs/store';
import type { Page } from '../router';
import { shell } from '../shell';
import { formatTime, formatTimestamp, isAtLeast } from '../ui';
import { html, render, repeat } from '../view';

/** What a kind of node says on its Logs page beyond what every node says. */
export interface LogsWords {
    /** The line under the heading. */
    subtitle?:  string;
}

/** What the filters above the list let through. */
export interface LogFilter {
    /** Every level from this one up. */
    level:   LogLevel;
    /** Any of these, the level counting as one; empty means "every tag". */
    tags:    ReadonlySet<string>;
    /** Somewhere in the message, whatever the case; empty means "every message". */
    search:  string;
}

/**
 * Whether the filters let this entry through.
 *
 * Any of the chosen tags, not all of them: somebody who picks "ocpp" and
 * "15118" wants to watch both conversations, not the empty set of lines that
 * are about both at once. The level counts as a tag, which is how "critical"
 * and "ocpp" can be picked together.
 */
export function matches(Entry: LogEntry, Filter: LogFilter): boolean {

    if (!isAtLeast(Entry.level, Filter.level))
        return false;

    if (Filter.tags.size > 0 &&
        ![ Entry.level, ...Entry.tags ].some(tag => Filter.tags.has(tag)))
        return false;

    const needle = Filter.search.trim().toLowerCase();

    return needle.length === 0 ||
           Entry.message.toLowerCase().includes(needle);

}

/**
 * One line, made once; a filter only ever toggles its "filtered-out" - and a
 * line that goes in while a filter is on goes in with it already set, so that
 * it never takes up room it is about to give back.
 *
 * Made as elements, not drawn by view.ts: a line is never drawn again, and
 * comparing a list of the thousands the node keeps with itself, for every line
 * the node writes, would put back the cost that making a line once took away
 * (see applyFilters). What the entry says goes in as text, which needs no
 * escaping.
 */
export function lineElement(Entry: LogEntry, FilteredOut = false): HTMLElement {

    const line  = document.createElement('div');
    line.className   = `line ${Entry.level}${FilteredOut ? ' filtered-out' : ''}`;
    line.dataset.id  = String(Entry.id);

    const time = document.createElement('time');
    time.dateTime     = Entry.timestamp;
    time.title        = formatTimestamp(Entry.timestamp);
    time.textContent  = formatTime(Entry.timestamp);

    line.append(time,
                span(`chip level ${Entry.level}`, Entry.level),
                ...Entry.tags.map(tag => span('chip tag', tag)),
                span('message', Entry.message));

    return line;

}

function span(Class: string, Text: string): HTMLSpanElement {
    const element = document.createElement('span');
    element.className    = Class;
    element.textContent  = Text;
    return element;
}

/** Lines in the order given, to go into the list at once. */
function linesOf(Entries: readonly LogEntry[], FilteredOut: (Index: number) => boolean = () => false): DocumentFragment {
    const lines = document.createDocumentFragment();
    Entries.forEach((entry, index) => lines.append(lineElement(entry, FilteredOut(index))));
    return lines;
}

/**
 * How the stream is doing, as the page says it beside its heading. Refused
 * for good is not reconnecting: the store has given up on a stream the node
 * will not open for this account, and a page that went on saying
 * "reconnecting ..." would be claiming something that is not happening,
 * beside a line that says the opposite.
 */
export function streamState(Connected: boolean, Refused: boolean): { text: string; tone: string } {
    return Connected ? { text: 'live',             tone: 'live' }
         : Refused   ? { text: 'stopped',          tone: 'down' }
         :             { text: 'reconnecting ...', tone: 'down' };
}

/**
 * How much of the log the list shows. "In memory": the node keeps that many
 * for the page, and writes its log to files besides - so "keeps the last 2000"
 * alone would say something about the files that is not true.
 */
export function countsText(Shown: number, Held: number, Capacity: number): string {
    return `${Shown} of ${Held} entries` +
           (Capacity > 0 ? ` (the ${config.nodeName} keeps the last ${Capacity} in memory)` : '');
}


/**
 * Everything that happens inside the node, as it happens.
 *
 * The entries arrive over one Server-Sent Events stream and go in at the top,
 * newest first, so that what just happened is where the eye already is and
 * nobody has to chase a growing list downwards. The filters work on what is
 * already in the browser, so changing one costs nothing and asks the node for
 * nothing. A list that is scrolled to the top follows along; scrolling down
 * stops that, which is what somebody reading an older line wants - and the
 * button that floats over the top of the list brings them back.
 *
 * The store keeps its entries oldest first and is left alone: that order is
 * what its own de-duplication and its bounded trim are written against. Only
 * what is drawn is reversed, by drawOrder and entryAt in logs/order.ts, which
 * the three places that map a line to an entry all go through.
 */
export function logsPage(Words: LogsWords = {}): Page {

    return {

        title: 'Logs',

        render({ root }) {

            const content = shell(root, {
                active:    '/logs',
                title:     'Logs',
                subtitle:  Words.subtitle ?? `Everything this ${config.nodeName} does, as it happens.`,
                actions:   stringHTML`
                    <span id="stream-state" class="stream-state"></span>
                    <button type="button" id="clear" class="btn small" title="Clear what this page shows; the ${config.nodeName} keeps its log">Clear view</button>
                `
            });

            // The note about the stream stands above the lines, not after
            // them: with the newest on top, "after them" is under as many as
            // the node keeps, where nobody would ever read it.
            render(content, html`

                <div class="log-filters">

                    <label class="filter-search">
                        <i class="fa-solid fa-magnifying-glass"></i>
                        <input type="search" id="search" placeholder="Search the messages ..." autocomplete="off" />
                    </label>

                    <label class="filter-level">
                        Level
                        <select id="level">
                            ${logLevels.map(level => html`
                                <option value="${level}" ?selected=${level === 'debug'}>${level}</option>
                            `)}
                        </select>
                    </label>

                    <label class="filter-follow">
                        <input type="checkbox" id="follow" checked />
                        Follow
                    </label>

                </div>

                <div id="tags" class="tag-filters"></div>

                <div class="log-pane">

                    <button type="button" id="to-newest" class="btn small jump-newest" hidden>
                        <i class="fa-solid fa-arrow-up"></i>
                        Jump to the newest
                    </button>

                    <div id="log" class="log" role="log" aria-live="polite" tabindex="0">
                        <div id="log-error" class="line error" hidden></div>
                        <div id="log-lines"></div>
                        <div id="log-empty" class="log-empty" hidden>
                            Nothing to show. The ${config.nodeName} has been quiet, or the filters are too narrow.
                        </div>
                    </div>

                </div>

                <div class="log-foot small muted">
                    <span id="counts"></span>
                </div>

            `);

            const list        = must<HTMLElement>       (content, '#log');
            const lineBox     = must<HTMLElement>       (content, '#log-lines');
            const emptyNote   = must<HTMLElement>       (content, '#log-empty');
            const errorNote   = must<HTMLElement>       (content, '#log-error');
            const tagBox      = must<HTMLElement>       (content, '#tags');
            const counts      = must<HTMLElement>       (content, '#counts');
            const toNewest    = must<HTMLButtonElement> (content, '#to-newest');
            const search      = must<HTMLInputElement>  (content, '#search');
            const level       = must<HTMLSelectElement> (content, '#level');
            const follow      = must<HTMLInputElement>  (content, '#follow');
            const streamShown = must<HTMLElement>       (root,    '#stream-state');
            const clear       = must<HTMLButtonElement> (root,    '#clear');

            /** The tags somebody has switched on; empty means "every tag". */
            const chosenTags = new Set<string>();

            let renderedTags = '';

            /** How many lines the filters are letting through, for the count below. */
            let shown = 0;

            /**
             * What the last correction still owes the view.
             *
             * scrollTop snaps to whole device pixels, so asking for 24.32 px on
             * a screen of one and a half sets 24 and drops the rest. Every line
             * of a log is the same height, so the same fraction is dropped
             * every time - this is not noise that cancels itself out but a
             * drift in one direction, a third of a pixel a line, a screenful
             * over a busy evening. Carried here and added to the next
             * correction, where the browser can finally take it.
             */
            let scrollDebt = 0;


            function filter(): LogFilter {
                return { level: level.value as LogLevel, tags: chosenTags, search: search.value };
            }

            function atNewest(): boolean {
                // A few pixels of slack: a list that is one rounding error short
                // of the top is, to the person reading it, at the top.
                return list.scrollTop <= 24;
            }

            function scrollToNewest(): void {
                list.scrollTop  = 0;
                scrollDebt      = 0;
                toNewest.hidden = true;
            }

            /**
             * Everything from the store, drawn once.
             *
             * Only for the two moments when what is held has actually changed
             * underneath: a snapshot reloaded from the node, and "Clear view".
             * Changing a filter is not one of them - see applyFilters below.
             */
            function redraw(): void {

                // Everything is drawn again, so nothing is owed from before.
                scrollDebt = 0;

                // Reversed for drawing only; the store keeps them oldest first.
                lineBox.replaceChildren(linesOf(drawOrder(logs.entries)));

                applyFilters();

                if (follow.checked)
                    scrollToNewest();

                drawTags();

            }

            /**
             * Which of the lines already drawn are wanted.
             *
             * A filter used to rebuild the whole list, which measured 597 ms for
             * one keystroke in the search box at 1959 entries, the layout that
             * follows included - more than half a second of frozen page per
             * character, and it grows with the log. Most of that was work
             * already done: the same lines built again from the same entries,
             * and every timestamp put through the locale formatter a second
             * time.
             *
             * A line is now made once and then only told whether it is wanted.
             * One keystroke then measured 50 ms at 2033 entries, layout
             * included as before: twelve times less. Deciding which lines are
             * wanted is the least of it, 2 ms for the same 1959; the rest is
             * the browser laying the list out again. Measured once more at
             * 2207 entries, the JavaScript alone went from 144 ms to 2 ms, and
             * the layout took 47 ms either way: this buys back the work the
             * page was doing twice, not the work of showing the answer.
             */
            function applyFilters(): void {

                // What is shown changes wholesale, so the fraction the last
                // correction was short is about a layout that no longer exists.
                scrollDebt = 0;

                const lines  = lineBox.children;
                const many   = Math.min(lines.length, logs.entries.length);
                const wanted = filter();

                shown = 0;

                for (let index = 0; index < many; index++) {

                    // Line 0 is the newest entry, which is the last one the
                    // store holds. Lines and entries are kept the same length,
                    // so this pairing stays exact - and entryAt is the one
                    // place it is written down, held by its tests to the
                    // drawOrder the drawing above goes by.
                    const yes = matches(entryAt(logs.entries, index)!, wanted);

                    lines[index]!.classList.toggle('filtered-out', !yes);

                    if (yes)
                        shown++;

                }

                emptyNote.hidden = shown > 0;

                updateCounts();

            }

            /** Only what is new: the usual case, and the cheap one. */
            function append(added: LogEntry[]): void {

                if (added.length > 0) {

                    const stick = follow.checked && atNewest();

                    // Whatever goes in above the line that is first on the
                    // screen right now pushes that line down by exactly what
                    // was added, so asking the line how far it moved is asking
                    // how much was added - and asking the rectangle answers in
                    // fractions of a pixel, where offsetTop and scrollHeight
                    // round to whole ones and leave a few behind on every
                    // batch.
                    //
                    // The first line that is shown, and not merely the first
                    // line: one a filter hides has no place on the screen,
                    // before or after, and taking it as the anchor would leave
                    // the view uncorrected - exactly while a filter is on -
                    // while the lines going in above the reader push theirs
                    // away.
                    const anchor     = lineBox.querySelector<HTMLElement>(':scope > .line:not(.filtered-out)');
                    const anchorWas  = anchor?.getBoundingClientRect().top ?? 0;

                    // Newest first inside the batch as well, so that a burst of
                    // entries reads top-down the way a single one does - drawn
                    // by the same drawOrder as the rest of the list, so that
                    // the two cannot come to disagree. Every entry gets its
                    // line, wanted or not, and only the new ones are asked
                    // about: asking the whole list again would put the cost of
                    // a filter change on every single line the node writes.
                    const batch  = drawOrder(added);
                    const now    = filter();
                    const wanted = batch.map(entry => matches(entry, now));

                    lineBox.prepend(linesOf(batch, index => !wanted[index]));

                    const any = wanted.some(yes => yes);

                    shown += wanted.filter(yes => yes).length;

                    // Read before the trimming below, which takes its lines off
                    // the bottom: that moves nothing above it, but it can take
                    // the anchor itself when the store has just wrapped - and
                    // then there is nothing left to hold still.
                    const grew = anchor?.isConnected
                                     ? anchor.getBoundingClientRect().top - anchorWas
                                     : 0;

                    // The node keeps a bounded log and so does this page; what
                    // fell out of the store has to leave the list as well. That
                    // is the oldest entry, which is now the last line rather
                    // than the first. The lines and the entries stay the same
                    // length, which is what lets a filter be applied by
                    // position above.
                    while (lineBox.childElementCount > logs.entries.length) {

                        if (lineBox.lastElementChild?.classList.contains('filtered-out') === false)
                            shown--;

                        lineBox.lastElementChild?.remove();

                    }

                    emptyNote.hidden = shown > 0;

                    // Where the filters want none of it, nothing new is shown
                    // and nothing on the screen moved.
                    if (any && stick)
                        scrollToNewest();

                    else if (any) {

                        // Put the view back by exactly as far as that line
                        // moved, and whatever the last correction was short,
                        // so the older one somebody stopped to read stays where
                        // they are looking instead of walking off the top at
                        // the speed the log fills. Measured here rather than
                        // left to the browser: see overflow-anchor in the
                        // stylesheet.
                        const asked    = list.scrollTop + grew + scrollDebt;

                        list.scrollTop = asked;

                        // What the browser took is not always what it was
                        // asked for. Only the snapping is worth carrying: when
                        // it refuses a larger jump than that - the list is at
                        // its end already, or the trimming above took the
                        // ground away - the difference is not a rounding
                        // error, and carrying it would be arguing with the
                        // browser rather than with the arithmetic.
                        const refused  = asked - list.scrollTop;
                        scrollDebt     = Math.abs(refused) < 1 ? refused : 0;

                        toNewest.hidden = false;

                    }

                    updateCounts();

                }

                drawTags();

            }

            function updateCounts(): void {
                counts.textContent = countsText(shown, logs.entries.length, logs.capacity);
            }

            /**
             * The tag buttons, drawn only when the node has learned a new tag
             * or one was switched. Drawn by view.ts, by the tag: the button
             * somebody switched, or moved to with the keyboard, is the same
             * button after the draw, and keeps the focus - drawn anew with
             * innerHTML, it was gone, and the focus with it, at every switch
             * and at every tag the node learned while it was there.
             */
            function drawTags(): void {

                const all = [...new Set([...logLevels, ...logs.tags])].sort();

                // NUL as the separator, written as an escape rather than as the
                // byte itself - the byte made this file binary to git, which
                // shows every change to it as a blob instead of a diff, and to
                // grep, which then skips it without a word. A tag may hold
                // anything a tag may hold, so the separator has to be the one
                // thing it cannot contain, or two different sets could share a
                // key.
                const key = all.join('\0') + '|' + [...chosenTags].sort().join('\0');

                if (key === renderedTags)
                    return;

                renderedTags = key;

                render(tagBox, html`
                    ${repeat(all, tag => tag, tag => html`
                        <button type="button" class="chip tag-button ${chosenTags.has(tag) ? 'on' : ''}" data-tag="${tag}"
                                aria-pressed="${chosenTags.has(tag)}" @click=${() => switchTag(tag)}>${tag}</button>
                    `)}
                    ${chosenTags.size > 0
                          ? html`<button type="button" class="chip tag-button clear-tags" data-tag="" @click=${() => switchTag('')}>all tags</button>`
                          : ''}
                `);

            }

            /** A tag switched on or off, or every tag, for '' - all of them again. */
            function switchTag(Tag: string): void {

                if (Tag === '')
                    chosenTags.clear();
                else if (chosenTags.has(Tag))
                    chosenTags.delete(Tag);
                else
                    chosenTags.add(Tag);

                renderedTags = '';
                applyFilters();
                drawTags();

            }

            function showStream(): void {
                const state = streamState(logs.streamConnected, logs.streamRefused);
                streamShown.className   = `stream-state ${state.tone}`;
                streamShown.textContent = state.text;
            }


            // Events

            search  .addEventListener('input',  () => applyFilters());
            level   .addEventListener('change', () => applyFilters());
            follow  .addEventListener('change', () => { if (follow.checked) scrollToNewest(); });
            toNewest.addEventListener('click',  () => scrollToNewest());
            clear   .addEventListener('click',  () => logs.clear());

            list.addEventListener('scroll', () => {
                if (atNewest())
                    toNewest.hidden = true;
            });

            const stopListening = logs.onChange(event => {

                switch (event.type) {

                    case 'entries':
                        append(event.added);
                        break;

                    case 'reloaded':
                        errorNote.hidden = true;
                        redraw();
                        break;

                    case 'stream':
                        showStream();
                        break;

                    case 'error':
                        errorNote.replaceChildren(span('message', event.text));
                        errorNote.hidden    = false;
                        // The store says why it stopped after it stopped, and
                        // the state beside the heading goes with what it says.
                        showStream();
                        break;

                }

            });

            showStream();
            redraw();

            // The store keeps running between pages - the log goes on filling
            // while somebody reads the configuration - so only this page's
            // listener goes.
            return stopListening;

        }

    };

}
