export async function GET(request) {
  const body = request.body;
  return fetch(request.url);
}
