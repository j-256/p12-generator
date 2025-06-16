// Expose NPM packages as UMD modules
import * as fflate from 'fflate';
import * as pvutils from 'pvutils';
import * as forge from 'node-forge';

window.fflate = fflate;
window.pvutils = pvutils;
window.forge = forge;
