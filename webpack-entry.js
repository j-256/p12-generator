// These npm packages don't provide browser-ready UMD builds, so we bundle them
// with Webpack and attach them to the window for access in browser scripts

import * as fflate from 'fflate';
import * as forge from 'node-forge';

window.fflate = fflate;
window.forge = forge;
