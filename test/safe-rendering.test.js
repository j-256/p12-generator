const assert = require('node:assert/strict');
const { afterEach, beforeEach, test } = require('node:test');

const {
    renderError,
    renderFileLists,
    resetGeneratedCertificate
} = require('../main.js');

const MALICIOUS_MARKUP = '<img src=x onerror="globalThis.compromised=true">.txt';

class FakeClassList {
    constructor() {
        this.values = new Set();
    }

    add(...names) {
        for (const name of names) {
            this.values.add(name);
        }
    }

    contains(name) {
        return this.values.has(name);
    }
}

class FakeNode {
    constructor(nodeName, value = '') {
        this.children = [];
        this.classList = new FakeClassList();
        this.nodeName = nodeName;
        this.value = value;
    }

    append(...children) {
        this.children.push(...children);
    }

    replaceChildren(...children) {
        this.children = [...children];
    }

    get textContent() {
        if (this.nodeName === '#text') {
            return this.value;
        }
        return this.children.map(child => child.textContent).join('');
    }

    set textContent(value) {
        this.children = [new FakeNode('#text', String(value))];
    }
}

function findElements(node, nodeName) {
    const matches = node.nodeName === nodeName ? [node] : [];

    return [
        ...matches,
        ...node.children.flatMap(child => findElements(child, nodeName))
    ];
}

beforeEach(() => {
    global.document = {
        createElement: name => new FakeNode(name.toUpperCase()),
        createTextNode: value => new FakeNode('#text', String(value))
    };
});

afterEach(() => {
    delete global.document;
});

test('renders uploaded filenames as text', () => {
    const container = new FakeNode('DIV');

    renderFileLists(container, ['required.txt'], [MALICIOUS_MARKUP]);

    assert.equal(container.textContent.includes(MALICIOUS_MARKUP), true);
    assert.equal(findElements(container, 'IMG').length, 2);
    assert.equal(findElements(container, 'IMG').some(icon => icon.src === 'x'), false);
});

test('renders parser errors as text', () => {
    const container = new FakeNode('DIV');

    renderError(container, ['Import failed:', MALICIOUS_MARKUP]);

    assert.equal(container.textContent, `Import failed:${MALICIOUS_MARKUP}`);
    assert.equal(findElements(container, 'BR').length, 1);
    assert.equal(findElements(container, 'IMG').length, 0);
});

test('clears a stale generated certificate', () => {
    const button = new FakeNode('BUTTON');
    const output = new FakeNode('DIV');

    button.onclick = () => {};
    output.textContent = 'Ready for download';
    global.document.getElementById = id => ({
        downloadButton: button,
        output
    })[id];

    resetGeneratedCertificate();

    assert.equal(button.classList.contains('hidden'), true);
    assert.equal(button.onclick, null);
    assert.equal(output.classList.contains('hidden'), true);
    assert.equal(output.textContent, '');
});
