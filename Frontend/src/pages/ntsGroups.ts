import type { NTSDisplayName } from '../api/client';

/**
 * The groups of time servers as the NTS page shows them in its tabs, and as
 * its "+" tab makes one.
 *
 * Apart from the page, because these decide what a tab is called and what the
 * node is asked to make - and a page that called a group by another name than
 * the one it was saved under would be a page nobody could find it on.
 */


/**
 * The tab that makes a group rather than showing one: in the address as
 * ?tab=_new. An underscore, which no group's name can have.
 */
export const NewGroupTab = '_new';


/**
 * Whether a text can be the name of a group, by the node's own rule: lower-case
 * letters, digits and hyphens, beginning with a letter.
 *
 * Said here as well as by the node so that the form can say it while it is
 * being typed into; the node says it again, and its word is the one that
 * counts.
 */
export function isGroupId(Text: string, MaxLength: number): boolean {
    return Text.length <= MaxLength && /^[a-z][a-z0-9-]*$/.test(Text);
}


/**
 * What a group is called on a tab and in a sentence: its display name in the
 * first of the reader's languages it has - the language itself, or the one it
 * is a dialect of - else the one meant for every language, else English, else
 * any; and "<id> time" where it has none, as "Legal time" or "Local time".
 *
 * @param Group      the group, by its name and its display name.
 * @param Languages  the reader's languages, the most wanted first; the
 *                   browser's by default.
 */
export function labelOf(Group:      { id: string; displayName: NTSDisplayName | null },
                        Languages:  readonly string[] = readersLanguages()): string {

    const name = Group.displayName;

    if (typeof name === 'string' && name.trim().length > 0)
        return name.trim();

    if (name !== null && typeof name === 'object') {

        const texts = new Map(Object.entries(name)
                                    .filter(([ , text ]) => typeof text === 'string' && text.trim().length > 0)
                                    .map(([ language, text ]) => [ language.toLowerCase(), text.trim() ]));

        for (const language of Languages.map(language => language.toLowerCase())) {
            const found = texts.get(language) ?? texts.get(language.split('-')[0]!);
            if (found !== undefined)
                return found;
        }

        const fallback = texts.get('*') ?? texts.get('en') ?? texts.values().next().value;

        if (fallback !== undefined)
            return fallback;

    }

    const said = `${Group.id} time`;

    return said.charAt(0).toUpperCase() + said.slice(1);

}


/** One line of the display name a new group is given: a language and what it is called in it. */
export interface DisplayNameRow {
    language:  string;
    text:      string;
}


/**
 * The display name as the node is to be told it: nothing where no line says
 * anything, one text where the only line is for every language - "*", or no
 * language given - and the texts by language otherwise.
 *
 * Or the sentence that says which line is not a language, which the node would
 * refuse in words about its file rather than about the form.
 */
export function displayNameOf(Rows: readonly DisplayNameRow[]): { name?: NTSDisplayName; error?: string } {

    const said = Rows.map(row => ({ language: row.language.trim().toLowerCase(), text: row.text.trim() }))
                     .filter(row => row.text.length > 0);

    if (said.length === 0)
        return {};

    if (said.length === 1 && (said[0]!.language === '' || said[0]!.language === '*'))
        return { name: said[0]!.text };

    const wrong = said.find(row => row.language !== '*' && !/^[a-z]{2,3}(-[a-z0-9]{2,8})*$/.test(row.language));

    if (wrong !== undefined)
        return { error: wrong.language === ''
                            ? `"${wrong.text}" is said in no language: name one, such as "en" or "de".`
                            : `"${wrong.language}" is not a language, which is written like "en", "de" or "de-at".` };

    return { name: Object.fromEntries(said.map(row => [ row.language, row.text ])) };

}


/** The reader's languages, as the browser has them - English where it says none. */
function readersLanguages(): readonly string[] {

    const languages = typeof navigator === 'undefined'
                          ? []
                          : navigator.languages?.length
                                ? navigator.languages
                                : navigator.language ? [ navigator.language ] : [];

    return languages.length > 0 ? languages : [ 'en' ];

}


/** The reader's first language without its region - "de" for "de-AT" - as the first line of a new display name offers it. */
export function firstLanguage(): string {
    return readersLanguages()[0]!.toLowerCase().split('-')[0]!;
}
