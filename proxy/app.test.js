const request = require('supertest')

const mockLPush = jest.fn().mockResolvedValue(1)
jest.mock('redis', () => ({
  createClient: () => ({
    isOpen: true,
    connect: jest.fn().mockResolvedValue(),
    on: jest.fn(),
    exists: jest.fn().mockResolvedValue(0),
    incr: jest.fn().mockResolvedValue(1),
    lPush: mockLPush,
    del: jest.fn().mockResolvedValue(1),
    hSet: jest.fn().mockResolvedValue(1),
  }),
}))
jest.mock('./db', () => ({ query: jest.fn().mockResolvedValue({ rows: [] }) }))

const app = require('./app')

test('없는 경로 → 404 + Redis 큐에 LPUSH', async () => {
  const res = await request(app).get('/api/v1/definitely-not-a-route')
  expect(res.status).toBe(404) // 매칭 라우트 없으면 404
  expect(mockLPush).toHaveBeenCalledTimes(1) // 보안 이벤트 큐에 넣었나
  const [queue, payload] = mockLPush.mock.calls[0]
  expect(queue).toBe('aegis:security-events')
  expect(JSON.parse(payload).action_on_match).toBe('no_route')
})
