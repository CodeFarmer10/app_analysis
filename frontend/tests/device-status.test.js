import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import {
  getUnavailableDetail,
  getUnavailableSummary,
} from '../src/utils/deviceStatus.js'

test('keeps a long recovery failure untruncated in the full detail', () => {
  const recoveryError = `wait_boot: ${'device remained unavailable; '.repeat(30)}`

  assert.equal(
    getUnavailableDetail({ status: 'error', recovery_error: recoveryError }),
    recoveryError,
  )
})

test('prioritizes recovery failure in the visible error summary', () => {
  assert.equal(
    getUnavailableSummary({
      status: 'error',
      recovery_error: 'wait_boot: recovery timed out',
      quarantine_reason: 'storage: less than 2 GB free',
    }),
    'wait_boot: recovery timed out',
  )
})

test('includes the original quarantine reason after the recovery failure', () => {
  assert.equal(
    getUnavailableDetail({
      status: 'error',
      recovery_error: 'verify_install: signature mismatch',
      quarantine_reason: 'storage: less than 2 GB free',
    }),
    'verify_install: signature mismatch\n原隔离原因：storage: less than 2 GB free',
  )
})

test('provides stable recovering and offline fallbacks', () => {
  assert.equal(getUnavailableSummary({ status: 'recovering' }), '设备正在自动恢复')
  assert.equal(getUnavailableDetail({ status: 'recovering' }), '设备正在自动恢复')
  assert.equal(getUnavailableSummary({ status: 'offline' }), '设备当前离线')
  assert.equal(getUnavailableDetail({ status: 'offline' }), '设备当前离线')
})

test('exposes unavailable details through hover and keyboard focus', async () => {
  const source = await readFile(
    new URL('../src/views/DeviceList.vue', import.meta.url),
    'utf8',
  )

  assert.match(source, /<a-tooltip[\s\S]*?:title="getUnavailableDetail\(record\)"/)
  assert.match(source, /:trigger="\['hover', 'focus'\]"/)
})
