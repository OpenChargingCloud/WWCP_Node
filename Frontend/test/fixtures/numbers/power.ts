/*
 * A page with no form that takes a number from an input of its own - the
 * shape of the charging station's power fields in evses.ts, which "a number on
 * a page" did not ask while it asked only the pages with a form. Emptied, the
 * field is 0 kW here.
 */

const field = document.querySelector<HTMLInputElement>('#max-power')!;

export const maxPower_kW = Number(field.value);
