import routes from './routes/index.js'

const api = routes()

api.listen(process.env.PORT, () => {
  console.log(`bluefox.email Tools API is listening on ${process.env.PORT}`)
})
