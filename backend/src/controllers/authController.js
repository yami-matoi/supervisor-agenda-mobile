const bcrypt = require("bcrypt");
const status = require("http-status");
const { Usuario, Profissional, PessoaFisica, ProfissionalEspecialidade, Especialidade } = require("../models");

exports.login = async (req, res) => {
  const { login, senha } = req.body;

  if (!login || !senha) {
    return res
      .status(status.BAD_REQUEST)
      .json({ message: "Login e senha são obrigatórios." });
  }

  try {
    const usuario = await Usuario.findOne({
      where: { LOGUSUARIO: login },
      attributes: ["ID_PROFISSIO", "LOGUSUARIO", "SENHAUSUA"],
      include: [
        {
          model: Profissional,
          as: "usuarioProfissional",
          where: { TIPOPROFI: 3 },
          attributes: ["IDPROFISSIO", "ID_PESSOAFIS", "TIPOPROFI"],
          include: [
            {
              model: PessoaFisica,
              as: "pessoa",
              attributes: ["NOMEPESSOA", "CPFPESSOA"],
            },
            {
              model: Especialidade,
              as: "especialidadesProfissional",
              attributes: ["IDESPEC", "CODESPEC", "DESCESPEC"],
              through: { attributes: [] },
            },
          ],
        },
      ],
    });

    if (!usuario) {
      return res.status(status.UNAUTHORIZED).json({
        message: "Usuário ou senha inválidos, ou acesso não permitido.",
      });
    }

    const senhaCorreta = await bcrypt.compare(senha, usuario.SENHAUSUA);

    if (!senhaCorreta) {
      return res
        .status(status.UNAUTHORIZED)
        .json({ message: "Senha incorreta." });
    }

    const profissional = usuario.usuarioProfissional;
    const pessoa = profissional.pessoa;

    const especialidadeObj = profissional.especialidadesProfissional?.[0];

    return res.status(status.OK).json({
      message: "Login bem-sucedido",
      usuario: {
        login: usuario.LOGUSUARIO,
        id_profissio: usuario.ID_PROFISSIO,
        cpf_profissio: pessoa.CPFPESSOA,
        nome_profissio: pessoa.NOMEPESSOA,
        tipo: profissional.TIPOPROFI,
        especialidade: especialidadeObj
          ? {
              id: especialidadeObj.IDESPEC,
              codigo: especialidadeObj.CODESPEC,
              descricao: especialidadeObj.DESCESPEC,
            }
          : null,
      },
    });
  } catch (error) {
    console.error("Erro no login:", error);
    return res
      .status(status.INTERNAL_SERVER_ERROR)
      .json({ message: "Erro interno no servidor." });
  }
};
