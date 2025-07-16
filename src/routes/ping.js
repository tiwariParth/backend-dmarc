export default apiServer => {
  apiServer.get('/v1/ping', () => {
    return {
      status: 200,
      result: 'pong'
    }
  })
}
