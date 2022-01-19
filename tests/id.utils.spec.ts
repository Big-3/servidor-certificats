import * as idUtils from '../src/utils/id.utils';
import {expect} from 'chai';
describe('IdUtils', () => {
    it('It should return a string', () => {
        expect(typeof idUtils.genRandomId()).to.equal('string');
    });
});