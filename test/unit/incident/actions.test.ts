import { describe, it, expect } from '@jest/globals';
import { parseActions, classifyAction, summariseActions, summariseActionCounts } from '../../../src/incident/analyse/actions.js';

describe('parseActions', () => {
  it('splits a batched ACTION_MESSAGE into named actions', () => {
    const m = '3$apex://SiteLoginFormController/ACTION$getForgotPasswordUrl=21;1$apex://SiteLoginFormController/ACTION$login=7;' +
      '1$aura://ApexActionController/ACTION$execute(AIR_GoogleRecaptchaController.getSiteKey)=2;' +
      '1$serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems=159';
    expect(parseActions(m)).toEqual([
      'SiteLoginFormController.getForgotPasswordUrl', 'SiteLoginFormController.login',
      'AIR_GoogleRecaptchaController.getSiteKey', 'SelectableListDataProviderController.getItems',
    ]);
  });
  it('returns [] for an empty message', () => { expect(parseActions('')).toEqual([]); });
});

describe('classifyAction', () => {
  it.each([
    ['SelectableListDataProviderController.getItems', 'data-access'],
    ['SeoAssistantController.getRecordAndTranslationData', 'data-access'],
    ['RecordUiController.executeGraphQL', 'data-access'],
    ['MyPortalController.getCases', 'data-access'],
    ['SiteLoginFormController.login', 'auth'],
    ['LightningForgotPasswordController.forgotPassword', 'auth'],
    ['SiteLoginFormController.getSelfRegistrationUrl', 'auth'],
    ['RichTextController.getParsedRichTextValue', 'plumbing'],
    ['HostConfigController.getConfigData', 'plumbing'],
    ['omnistudio__FlexRuntime.logUsageEvents', 'plumbing'],
    ['AIR_GoogleRecaptchaController.getSiteKey', 'plumbing'],
    ['ComponentController.reportFailedAction', 'plumbing'],
  ])('%s → %s', (name, cls) => { expect(classifyAction(name)).toBe(cls); });
});

describe('summariseActions', () => {
  it('counts per class and per name, most frequent first', () => {
    const s = summariseActions([
      '1$serviceComponent://x.SelectableListDataProviderController/ACTION$getItems=1',
      '1$serviceComponent://x.SelectableListDataProviderController/ACTION$getItems=1;1$apex://SiteLoginFormController/ACTION$login=1',
      '',
    ]);
    expect(s.byClass).toEqual({ 'data-access': 2, auth: 1, plumbing: 0, unknown: 0 });
    expect(s.byName[0]).toEqual({ name: 'SelectableListDataProviderController.getItems', cls: 'data-access', count: 2 });
  });
  it('summariseActionCounts over two count maps equals summariseActions over the messages', () => {
    const a = '1$serviceComponent://x.SelectableListDataProviderController/ACTION$getItems=1;1$apex://SiteLoginFormController/ACTION$login=1';
    const b = '1$serviceComponent://x.SelectableListDataProviderController/ACTION$getItems=1';
    const counts: Array<Record<string, number>> = [
      { 'SelectableListDataProviderController.getItems': 1, 'SiteLoginFormController.login': 1 },
      { 'SelectableListDataProviderController.getItems': 1 },
    ];
    expect(summariseActionCounts(counts)).toEqual(summariseActions([a, b]));
  });
});
