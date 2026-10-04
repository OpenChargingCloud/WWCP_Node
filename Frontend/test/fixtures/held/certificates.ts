/*
 * A kind's certificates page that hands its forms to the node's page as
 * sections, which holds them - the shape of the energy meter's signing
 * requests since WWCP_Node cb04b89.
 */

export const options = {
    sections: () => [ { below: 'presents', draw: () => '<form id="request-form"><input name="subject" /></form>' } ]
};
