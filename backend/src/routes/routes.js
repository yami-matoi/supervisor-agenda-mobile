const express = require("express");
const router = express.Router();
const AgendaController = require("../controllers/agendaController.js");
const dataController = require("../controllers/dataController.js");
const ProfissionaisController = require("../controllers/profissionaisController.js");
const authController = require("../controllers/authController.js");
const usuariosController = require("../controllers/usuariosController.js");

router.post("/auth/login", authController.login);
router.get("/usuarios/login/:login", usuariosController.buscarPorLogin);

// Rota para buscar profissionais por especialidade
router.get(
  "/especialidade/:especialidadeId/profissionais",
  dataController.getProfissionaisPorEspecialidade
);

// Rota para buscar procedimentos por especialidade
router.get(
  "/especialidade/:especialidadeId/procedimentos",
  dataController.getProcedimentosPorEspecialidade
);

router.post("/agenda", AgendaController.Insert);
router.get("/agenda", AgendaController.SearchAll);
router.get("/cancelados", AgendaController.SearchAllCanceleds);
router.put("/agenda/:id/delete", AgendaController.Delete);
router.get("/agenda/:id", AgendaController.SearchOne);
router.put("/agenda/:id", AgendaController.Update);

// Endpoints para obter dados
router.get("/especialidades", dataController.getEspecialidades);
router.get("/procedimentos", dataController.getProcedimentos);
router.get("/pessoafis", dataController.getPessoaFis);
// router.get("/ag_profissionais", dataController.getAgProfissionais);

// Endpoints específicos de profissionais
router.get("/profissionais/", ProfissionaisController.SearchAll);
router.get("/profissionais/nextId", ProfissionaisController.GetNextProfId);
router.get(
  "/profissionais/supervisores",
  ProfissionaisController.GetSupervisores
);
router.get("/profissionais/:id", ProfissionaisController.SearchOne);
router.post("/cadastro_profissional", ProfissionaisController.Insert);

module.exports = router;
