import * as idUtils from '../src/utils/id.utils';
import {expect} from 'chai';
describe('IdUtils', () => {
    it('It should return a string', () => {
        expect(typeof idUtils.genRandomId()).to.equal('string');
    });
});

describe('IdUtils', () => {
    it('It should return an integer in a string form', () => {
        expect(typeof idUtils.getRandomInt(1,Number.MAX_SAFE_INTEGER)).to.equal('string');
    });
});