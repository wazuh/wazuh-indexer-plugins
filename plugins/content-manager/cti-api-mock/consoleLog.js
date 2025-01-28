console.log(
    JSON.stringify(
      JSON.parse(context.request.body),
      undefined,
      2
    )
  )