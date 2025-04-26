const validate = (schema) => (req, res, next) => {
    try {
        const result = schema.validate(req.body);

        if (result.error) {

            return res.json({
                code: 400,
                msg: 'Invalid parameter',
                detail: result.error.message.replace(/"/g, ""),
            });
        }

        next();
    } catch (error) {
        return res.status(500).json({
          code: 999,
          message: "Internal Server Error",
        });
    }
};