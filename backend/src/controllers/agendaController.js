const { Op } = require("sequelize");
const {
  Agenda,
  Profissional,
  PessoaFisica,
  Procedimento,
  Especialidade,
} = require("../models");
const status = require("http-status");

// Inserir novo agendamento
exports.Insert = (req, res, next) => {
  const {
    ID_PROCED,
    ID_PESSOAFIS,
    ID_PROFISSIO,
    DATAABERT,
    DESCRCOMP,
    SOLICMASTER,
  } = req.body;

  Agenda.create({
    ID_PROCED,
    ID_PESSOAFIS,
    ID_PROFISSIO,
    DATAABERT,
    DESCRCOMP,
    SOLICMASTER,
  })
    .then((agenda) => res.status(status.OK).send(agenda))
    .catch((error) => next(error));
};

// Buscar todos os agendamentos com joins



exports.SearchAll = async (req, res, next) => {
  try {
    const { id_espec, id_profissio } = req.query;

    const agenda = await Agenda.findAll({
      where: {
        SITUAGEN: { [Op.ne]: 3 },
        ...(id_profissio && { ID_PROFISSIO: Number(id_profissio) }),
      },
      include: [
        {
          model: PessoaFisica,
          as: "pessoaFisAgenda",
          attributes: ["NOMEPESSOA"],
        },
        {
          model: Profissional,
          as: "profissional",
          include: [
            {
              model: PessoaFisica,
              as: "pessoa",
              attributes: ["NOMEPESSOA"],
            },
          ],
        },
        {
          model: Procedimento,
          as: "procedimento",
          required: !!id_espec, // força INNER JOIN se especialidade for usada
          include: [
            {
              model: Especialidade,
              as: "especialidades",
              through: { attributes: [] },
              attributes: ["IDESPEC", "DESCESPEC"],
              where: id_espec ? { IDESPEC: Number(id_espec) } : undefined,
              required: !!id_espec,
            },
          ],
        },
      ],
    });

    res.status(200).send(agenda);
  } catch (error) {
    console.error("Erro ao buscar agenda:", error);
    res.status(500).json({ message: "Erro ao buscar agenda" });
  }
};



exports.SearchAllCanceleds = async (req, res, next) => {
  try {
    const agenda = await Agenda.findAll({
      where: {
        SITUAGEN: 3,
      },
      include: [
        {
          model: PessoaFisica,
          as: "pessoaFisAgenda",
          attributes: ["NOMEPESSOA"],
        },
        {
          model: Profissional,
          as: "profissional",
          include: [
            {
              model: PessoaFisica,
              as: "pessoa",
              attributes: ["NOMEPESSOA"],
            },
          ],
        },
        {
          model: Procedimento,
          as: "procedimento",
          include: [
            {
              model: Especialidade,
              as: "especialidades",
              through: { attributes: [] },
              attributes: ["IDESPEC", "DESCESPEC"],
            },
          ],
        },
      ],
    });

    res.status(status.OK).send(agenda);
  } catch (error) {
    next(error);
  }
};

// Buscar um agendamento específico com joins
exports.SearchOne = (req, res, next) => {
  const id_agenda = req.params.id;

  Agenda.findByPk(id_agenda, {
    include: [
      {
        model: Profissional,
        as: "profissional",
        include: [
          {
            model: PessoaFisica,
            as: "pessoa",
            attributes: ["NOMEPESSOA"],
          },
          {
            model: Especialidade,
            as: "especialidade",
            attributes: ["DESCESPEC"],
          },
        ],
      },
      {
        model: Procedimento,
        as: "procedimento",
        // 🚫 Removido o include de especialidade, pois não existe diretamente no model
      },
    ],
  })
    .then((agenda) => {
      if (agenda) {
        res.status(status.OK).send(agenda);
      } else {
        res.status(status.NOT_FOUND).send();
      }
    })
    .catch((error) => next(error));
};

// Atualizar um agendamento
exports.Update = (req, res, next) => {
  const id_agenda = req.params.id;
  const {
    ID_PROCED,
    ID_PROFISSIO,
    DATAABERT,
    DATANOVA,
    DESCRCOMP,
    SITUAGEN,
    SOLICMASTER,
    MOTIALT,
  } = req.body;

  Agenda.findByPk(id_agenda)
    .then((agenda) => {
      if (agenda) {
        return agenda.update({
          ID_PROCED,
          ID_PROFISSIO,
          DESCRCOMP,
          DATAABERT,
          DATANOVA,
          SITUAGEN,
          SOLICMASTER,
          MOTIALT,
        });
      } else {
        return res.status(status.NOT_FOUND).send();
      }
    })
    .then(() => res.status(status.OK).send())
    .catch((error) => next(error));
};

// Deletar agendamento
exports.Delete = (req, res, next) => {
  const id_agenda = req.params.id;
  const { SITUAGEN, SOLICMASTER } = req.body;

  Agenda.findByPk(id_agenda)
    .then((agenda) => {
      if (agenda) {
        return agenda.update({ SITUAGEN, SOLICMASTER });
      } else {
        return res.status(status.NOT_FOUND).send();
      }
    })
    .then(() => res.status(status.OK).send())
    .catch((error) => next(error));
};
