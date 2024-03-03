module.exports = fn => (req, res, next) => {
  fn(req, res, next).catch(next);
};
//Higher order function, It expects a async func as para,
//which will return promise and inturn the catch will trigger
